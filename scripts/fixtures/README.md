# Corpus JPEG fixture

`corpus.jpg` is an original synthetic 16×16 RGB image with a solid `(32, 96, 160)`
color, used for both JPEG files in the Figure 5 replacement corpus. It is not an
image from the paper. No external image or license attribution is required.

It was created once with Pillow 9.4.0:

```python
from PIL import Image
Image.new("RGB", (16, 16), (32, 96, 160)).save(
    "scripts/fixtures/corpus.jpg", format="JPEG", quality=90,
    subsampling=0, optimize=False, progressive=False,
)
```

SHA-256: `caf72c89db38ea511813ecb782bc3a6deec2385c10afe1a77044c2c1b1cb1e3f`.
Use the checked-in bytes, not a fresh JPEG encoding, to reproduce the corpus;
different Pillow/libjpeg versions may encode the same pixels differently.
