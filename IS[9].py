"""Cryptographic watermarking tool with GUI.

Features:
- Embed an encrypted watermark message into the least-significant bits of an RGB image.
- Extract and decrypt the watermark message.
- CLI and Tkinter GUI front-ends.

Dependencies: pillow, cryptography
Install with: pip install pillow cryptography
"""
from __future__ import annotations
import argparse
import base64
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Tuple

from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Try import tkinter for GUI; keep program usable without GUI
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception as exc:  # pragma: no cover - GUI not available
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore
    GUI_IMPORT_ERROR = exc
else:
    GUI_IMPORT_ERROR = None

MAGIC = b"WMK1"
HEADER_SIZE = len(MAGIC) + 16 + 4  # magic + salt + length


class WatermarkError(Exception):
    """Raised when watermark embedding or extraction fails."""


@dataclass
class WatermarkPayload:
    salt: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        if len(self.salt) != 16:
            raise ValueError("Salt must be 16 bytes long")
        length_bytes = len(self.ciphertext).to_bytes(4, "big")
        return MAGIC + self.salt + length_bytes + self.ciphertext

    @classmethod
    def deserialize(cls, data: bytes) -> "WatermarkPayload":
        if len(data) < HEADER_SIZE:
            raise WatermarkError("Data too short to contain a watermark")
        if not data.startswith(MAGIC):
            raise WatermarkError("Watermark magic header not found")
        salt = data[len(MAGIC) : len(MAGIC) + 16]
        length = int.from_bytes(data[len(MAGIC) + 16 : len(MAGIC) + 16 + 4], "big")
        ciphertext = data[HEADER_SIZE : HEADER_SIZE + length]
        if len(ciphertext) != length:
            raise WatermarkError("Watermark ciphertext length mismatch")
        return cls(salt=salt, ciphertext=ciphertext)


class Watermarker:
    """Handles encryption and bit-level embedding/extraction."""

    def __init__(self, iterations: int = 390_000) -> None:
        self.iterations = iterations

    def derive_key(self, password: str, salt: bytes) -> bytes:
        if not password:
            raise WatermarkError("Password is required for cryptographic watermarking")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        return key

    def encrypt(self, message: str, password: str) -> WatermarkPayload:
        if not message:
            raise WatermarkError("Watermark message cannot be empty")
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        token = Fernet(key).encrypt(message.encode("utf-8"))
        return WatermarkPayload(salt=salt, ciphertext=token)

    def decrypt(self, payload: WatermarkPayload, password: str) -> str:
        key = self.derive_key(password, payload.salt)
        try:
            decrypted = Fernet(key).decrypt(payload.ciphertext)
        except Exception as exc:  # pragma: no cover - cryptography specific errors
            raise WatermarkError("Failed to decrypt watermark. Check password.") from exc
        return decrypted.decode("utf-8")

    def embed(self, input_path: Path, output_path: Path, message: str, password: str) -> None:
        payload = self.encrypt(message, password)
        data = payload.serialize()
        self._embed_bytes(input_path, output_path, data)

    def extract(self, input_path: Path, password: str) -> str:
        data = self._extract_bytes(input_path)
        payload = WatermarkPayload.deserialize(data)
        return self.decrypt(payload, password)

    # Bitwise helpers
    def _embed_bytes(self, input_path: Path, output_path: Path, data: bytes) -> None:
        image = Image.open(input_path).convert("RGB")
        img_bytes = bytearray(image.tobytes())
        bit_stream = self._bytes_to_bits(data)
        total_bits = len(bit_stream)
        capacity = len(img_bytes)  # one bit per image byte (LSB)
        if total_bits > capacity:
            raise WatermarkError(
                f"Watermark is too large for this image. Needed {total_bits} bits, have {capacity}."
            )
        for idx, bit in enumerate(bit_stream):
            img_bytes[idx] = (img_bytes[idx] & 0xFE) | bit
        watermarked = Image.frombytes("RGB", image.size, bytes(img_bytes))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        watermarked.save(output_path)

    def _extract_bytes(self, input_path: Path) -> bytes:
        image = Image.open(input_path).convert("RGB")
        img_bytes = image.tobytes()
        bits = [(b & 1) for b in img_bytes]
        header_bits_count = HEADER_SIZE * 8
        if len(bits) < header_bits_count:
            raise WatermarkError("Image is too small to contain a watermark header")
        header_bytes = self._bits_to_bytes(bits[:header_bits_count])
        if not header_bytes.startswith(MAGIC):
            raise WatermarkError("Watermark magic header not found")
        length = int.from_bytes(header_bytes[len(MAGIC) + 16 : len(MAGIC) + 16 + 4], "big")
        total_bytes = HEADER_SIZE + length
        needed_bits = total_bytes * 8
        if len(bits) < needed_bits:
            raise WatermarkError("Image does not contain the full watermark payload")
        payload_bytes = self._bits_to_bytes(bits[:needed_bits])
        return payload_bytes

    @staticmethod
    def _bytes_to_bits(data: bytes) -> Tuple[int, ...]:
        return tuple(((byte >> bit) & 1) for byte in data for bit in reversed(range(8)))

    @staticmethod
    def _bits_to_bytes(bits: Iterable[int]) -> bytes:
        out = bytearray()
        bits_list = list(bits)
        for idx in range(0, len(bits_list), 8):
            byte_bits = bits_list[idx : idx + 8]
            if len(byte_bits) < 8:
                break
            value = 0
            for bit in byte_bits:
                value = (value << 1) | (bit & 1)
            out.append(value)
        return bytes(out)


# GUI implementation
class WatermarkApp:
    def __init__(self, root: Any) -> None:
        if tk is None or ttk is None or filedialog is None or messagebox is None:
            raise RuntimeError(f"Tkinter is not available: {GUI_IMPORT_ERROR}")
        self.root = root
        root.title("Cryptographic Image Watermarker")
        root.resizable(False, False)
        self.watermarker = Watermarker()
        self._build_ui()

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)
        self.embed_tab = ttk.Frame(notebook)
        self.extract_tab = ttk.Frame(notebook)
        notebook.add(self.embed_tab, text="Embed Watermark")
        notebook.add(self.extract_tab, text="Extract Watermark")
        self._build_embed_tab()
        self._build_extract_tab()

    # Embed Tab
    def _build_embed_tab(self) -> None:
        frame = self.embed_tab
        self.embed_image_path = tk.StringVar()
        self.embed_output_path = tk.StringVar()
        self.embed_message = tk.StringVar()
        self.embed_password = tk.StringVar()

        ttk.Label(frame, text="Choose an image to watermark:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.embed_image_path, width=40).grid(row=1, column=0, padx=(0, 8), pady=4)
        ttk.Button(frame, text="Browse", command=self._select_embed_image).grid(row=1, column=1, pady=4)

        ttk.Label(frame, text="Watermark message:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.embed_message, width=40).grid(row=3, column=0, columnspan=2, pady=4, sticky="we")

        ttk.Label(frame, text="Password (encryption key):").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.embed_password, width=40, show="*").grid(row=5, column=0, columnspan=2, pady=4, sticky="we")

        ttk.Label(frame, text="Save watermarked image as:").grid(row=6, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.embed_output_path, width=40).grid(row=7, column=0, padx=(0, 8), pady=4)
        ttk.Button(frame, text="Save As", command=self._select_output_path).grid(row=7, column=1, pady=4)

        ttk.Button(frame, text="Embed", command=self._handle_embed).grid(row=8, column=0, columnspan=2, pady=(12, 0))

    def _select_embed_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")],
        )
        if path:
            self.embed_image_path.set(path)
            if not self.embed_output_path.get():
                suggested = self._suggest_output_path(Path(path))
                self.embed_output_path.set(str(suggested))

    def _select_output_path(self) -> None:
        initial = self.embed_output_path.get() or "watermarked.png"
        path = filedialog.asksaveasfilename(
            title="Save watermarked image",
            initialfile=Path(initial).name,
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("All files", "*.*")],
        )
        if path:
            self.embed_output_path.set(path)

    def _handle_embed(self) -> None:
        try:
            input_path = self._require_path(self.embed_image_path.get(), "Please select an input image.")
            output_path = Path(self.embed_output_path.get() or self._suggest_output_path(input_path))
            message = self.embed_message.get().strip()
            password = self.embed_password.get().strip()
            self.watermarker.embed(input_path, output_path, message, password)
        except Exception as exc:
            messagebox.showerror("Embedding failed", str(exc))
        else:
            messagebox.showinfo("Success", f"Watermarked image saved to:\n{output_path}")

    # Extract Tab
    def _build_extract_tab(self) -> None:
        frame = self.extract_tab
        self.extract_image_path = tk.StringVar()
        self.extract_password = tk.StringVar()
        self.extract_message = tk.StringVar()

        ttk.Label(frame, text="Choose a watermarked image:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.extract_image_path, width=40).grid(row=1, column=0, padx=(0, 8), pady=4)
        ttk.Button(frame, text="Browse", command=self._select_extract_image).grid(row=1, column=1, pady=4)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.extract_password, width=40, show="*").grid(row=3, column=0, columnspan=2, pady=4, sticky="we")

        ttk.Button(frame, text="Extract", command=self._handle_extract).grid(row=4, column=0, columnspan=2, pady=(12, 0))

        ttk.Label(frame, text="Extracted watermark:").grid(row=5, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(frame, textvariable=self.extract_message, width=40, state="readonly").grid(row=6, column=0, columnspan=2, pady=4, sticky="we")

    def _select_extract_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select watermarked image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")],
        )
        if path:
            self.extract_image_path.set(path)

    def _handle_extract(self) -> None:
        try:
            input_path = self._require_path(self.extract_image_path.get(), "Please select a watermarked image.")
            password = self.extract_password.get().strip()
            message = self.watermarker.extract(input_path, password)
        except Exception as exc:
            messagebox.showerror("Extraction failed", str(exc))
        else:
            self.extract_message.set(message)
            messagebox.showinfo("Success", "Watermark extracted successfully.")

    # Helpers
    def _require_path(self, value: str, error_message: str) -> Path:
        path = Path(value)
        if not value:
            raise WatermarkError(error_message)
        if not path.exists():
            raise WatermarkError(f"File not found: {value}")
        return path

    @staticmethod
    def _suggest_output_path(input_path: Path) -> Path:
        return input_path.with_name(f"{input_path.stem}_watermarked.png")


# CLI helpers
def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cryptographic watermarking tool")
    parser.add_argument("mode", choices=["embed", "extract", "gui"], help="Run mode")
    parser.add_argument("--input", "-i", type=Path, help="Input image path")
    parser.add_argument("--output", "-o", type=Path, help="Output image path (embed mode)")
    parser.add_argument("--message", "-m", help="Watermark message (embed mode)")
    parser.add_argument("--password", "-p", help="Password for encryption/decryption")
    return parser.parse_args(list(argv))


def run_cli(args: argparse.Namespace) -> None:
    watermarker = Watermarker()
    mode = args.mode
    if mode == "gui":
        run_gui()
        return
    if args.input is None or args.password is None:
        raise SystemExit("--input and --password are required")
    if mode == "embed":
        if args.message is None:
            raise SystemExit("--message is required in embed mode")
        output = args.output or args.input.with_name(f"{args.input.stem}_watermarked.png")
        watermarker.embed(args.input, output, args.message, args.password)
        print(f"Watermarked image saved to {output}")
    elif mode == "extract":
        message = watermarker.extract(args.input, args.password)
        print(message)
    else:
        raise SystemExit(f"Unknown mode: {mode}")


def run_gui() -> None:
    if tk is None:
        raise RuntimeError(f"Tkinter GUI is not available: {GUI_IMPORT_ERROR}")
    root = tk.Tk()
    app = WatermarkApp(root)
    root.mainloop()


def main(argv: Iterable[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        if tk is not None:
            run_gui()
        else:
            raise SystemExit("GUI is unavailable. Use CLI: python watermark_app.py embed ...")
        return
    args = _parse_args(argv)
    run_cli(args)


if __name__ == "__main__":
    main()
