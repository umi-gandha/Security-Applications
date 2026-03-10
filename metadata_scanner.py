import exifread
import os
import base64
from PIL import Image
from datetime import datetime

IMAGE_FOLDER = "Images/"
IMAGE_FILES = [
    "Activation.png", "Brain-Channel.png", "Brain.png",
    "Chemicals.png", "Dopamine.png", "Music.png"
]

def decode_covert_message(val):
    """Part 2: Attempts to decode Base64 obfuscation used by attackers."""
    try:
        if len(val) > 10 and " " not in val:
            return base64.b64decode(val).decode('utf-8')
    except:
        pass
    return val

def run_forensic_audit(filename):
    path = os.path.join(IMAGE_FOLDER, filename)
    if not os.path.exists(path):
        return None

    audit = {
        "name": filename,
        "score": 0,
        "secret": "",
        "categories": {
            "Hidden Secret": "None",
            "GPS Leak": "No",
            "Timestamp Anomaly": "No",
            "Editing Traces": "None"
        }
    }

    fs_mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y:%m:%d')

    with open(path, 'rb') as f:
        exif_tags = exifread.process_file(f)
    
    try:
        pil_info = Image.open(path).info
    except:
        pil_info = {}

    covert_fields = [
        ('EXIF UserComment', 'UserComment'), ('Image ImageDescription', 'ImageDescription'), 
        ('EXIF MakerNote', 'MakerNote'), ('Image Software', 'Software'), 
        ('Image Copyright', 'Copyright'), ('GPS GPSDestDistance', 'GPSDestDistance')
    ]
    
    for exif_key, pil_key in covert_fields:
        val = str(exif_tags.get(exif_key, pil_info.get(pil_key, "")))
        if len(val) > 15:
            audit["score"] += 10
            audit["secret"] = decode_covert_message(val)
            audit["categories"]["Hidden Secret"] = f"Detected in {pil_key}"
            break

    if 'GPS GPSLatitude' in exif_tags or 'GPS' in pil_info:
        audit["score"] += 5
        audit["categories"]["GPS Leak"] = "Yes (Coordinates Found)"

    exif_time = str(exif_tags.get('EXIF DateTimeOriginal', ""))
    if exif_time and fs_mtime not in exif_time:
        audit["score"] += 5
        audit["categories"]["Timestamp Anomaly"] = f"FS ({fs_mtime}) != EXIF ({exif_time[:10]})"

    software = str(exif_tags.get('Image Software', pil_info.get('Software', ""))).lower()
    if any(app in software for app in ['photoshop', 'gimp', 'adobe']):
        audit["score"] += 5
        audit["categories"]["Editing Traces"] = f"Software: {software}"

    return audit

def main():
    print(f"{'='*105}")
    print(f"{'LAB 6 FORENSIC AUDIT: COVERT CHANNEL & RISK ANALYSIS':^105}")
    print(f"{'='*105}")
    print(f"{'FILENAME':<18} | {'SCORE':<5} | {'SECRET PART':<15} | {'GPS':<12} | {'ANOMALY':<15} | {'EDITING'}")
    print(f"{'-'*105}")

    full_reconstructed_message = []
    for img in IMAGE_FILES:
        res = run_forensic_audit(img)
        if res:
            print(f"{res['name']:<18} | {res['score']:<5} | {res['secret']:<15} | "
                  f"{res['categories']['GPS Leak']:<12} | {res['categories']['Timestamp Anomaly']:<15} | "
                  f"{res['categories']['Editing Traces']}")
            if res["secret"]:
                full_reconstructed_message.append(res["secret"])
        else:
            print(f"{img:<18} | [!] FILE NOT FOUND")

    print(f"{'='*105}")
    print(f"RECONSTRUCTED FULL SECRET: {' '.join(full_reconstructed_message)}")
    print(f"{'='*105}")

if __name__ == "__main__":
    main()