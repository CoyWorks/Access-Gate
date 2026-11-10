# Code cards, PDF and QR

On **Create batch**, choose **Codes and text download**, **Printable cards** or **PDF cards**. Print/PDF support optional QR codes. This is the only opportunity to export full codes: they are not stored in plaintext and cannot be downloaded from an existing batch later.

- A4 cards contain the code, batch name, activation window in Europe/Amsterdam and access duration. Each code remains single-use.
- Printable cards have a Print / save as PDF button and six cards per A4 page. Browser headers/footers should be disabled for printing.
- PDF is a direct attachment with six cards per page and embedded Unicode fonts. Large batches use multiple pages.
- Exports support up to 1,000 codes; QR exports are limited to 200 per batch to bound synchronous generation time.
- A QR opens the canonical HTTPS portal with a `#code=...` fragment. The fragment is not sent to the server. JavaScript fills the field and removes it from the current history entry. The visitor must press **Activate**; scanning alone never consumes the code. JavaScript is required for QR prefill; codes can always be entered manually.
- Export responses are not cached. Keep printed cards and PDFs private: possession of an unused code permits activation. QR codes are generated locally, not by an external service.
- If rendering fails after creation, the already-created batch's full codes are shown once as a text fallback. Save those codes before leaving; the error path never generates a replacement batch.

The normal updater installs Ubuntu's `python3-reportlab` and `fonts-dejavu-core`. No additional service or external QR API is used. Automated tests cover permissions, CSRF, format validation before generation, Unicode/special characters, large batches, PDF pages, QR prefill without activation and the rendering-error fallback.
