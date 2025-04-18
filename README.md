# FitnessOverlays 🏃📱

[Live Website → fitnessoverlays.onrender.com](https://fitnessoverlays.onrender.com/)

## Turn Your Strava Activities into Awesome Overlays

FitnessOverlays lets you quickly create stylish overlays from your Strava activities, ready to share on Instagram Stories or wherever you like.

---

## Features

* **Strava Connect**: Securely link your account with a single click.
* **Paste & Go**: Just drop in your Strava activity link—no manual data entry.
* **Customize Everything**: Choose which metrics to show, pick colors, adjust text size, alignment, and columns.
* **Story-Ready**: Get transparent, high-res overlays sized perfectly for Instagram Stories.
* **Copy or Save**: Copy overlay text, copy the cropped overlay image, or save it (mobile and desktop supported).

---

## How It Works

1. **Connect**: Click the Strava button to securely link your account.
2. **Input Activity**: Paste your Strava activity link or ID on the input page.
3. **Customize**: Select which stats to show, pick colors, adjust text size, alignment, and columns.
4. **Copy & Share**: Copy the overlay image (with transparent background) or text, and share it in your Instagram Story or anywhere you like.

---

## Overlay Data Options

### Key Metrics (if available from Strava)

* **Distance** (e.g., `11.01 km`)
* **Moving Time** (e.g., `1h 5m 52s`)
* **Pace** (e.g., `5:58 /km`)
* **Avg Speed** (e.g., `10.1 km/h`)
* **Avg Heart Rate** (e.g., `159 bpm`)
* **Max Heart Rate** (e.g., `187 bpm`)
* **Calories** (e.g., `809`)
* **Elevation Gain** (e.g., `25 m`)

### Customization Options

* **Metric Selection**: Enable/disable any metric (buttons auto-disable if data is missing)
* **Text Color**: Use the color wheel for any overlay text color
* **Text Alignment**: Cycle between left, center, right
* **Label/Value Size**: Cycle between small, medium, large for both label and value
* **Columns**: Show metrics in 1–4 columns
* **Reset**: One-click reset to default overlay settings

### Export & Sharing

* **Copy Text**: Copies all selected metrics as plain text
* **Copy Image**: Copies a cropped, high-res PNG of the overlay (transparent background)
* **Save Image**: Download the overlay image (desktop) or long-press to save (mobile)

---

## Example Overlays

See the [live site](https://fitnessoverlays.onrender.com/) for real examples and a carousel of sample overlays.

---

## Quick Start for Developers

See `NOTES.md` for full setup instructions, including local development, Docker, and Tailwind CSS build steps.

* **Backend:** Python (Flask), SQLite (`activities.db`), Strava API
* **Frontend:** HTML, Vanilla JS, Tailwind CSS

---

## License

&copy; 2025 FitnessOverlays - Licensed under [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html)

![Powered by Strava](static/images/api_logo_pwrdBy_strava_horiz_orange.svg)
