"""Render the reportsieve narrated demo: real command output + edge-tts narration.

Usage: python demo/render.py [--gif]   (needs ffmpeg, edge-tts, Pillow, bwrap, cc, network, reportsieve in /tmp/rsvenv)
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
SDKBIN = "/tmp/rsvenv/bin"
SANDBOX = "/tmp/rsdemo"
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80), "2": (130, 135, 145), "36": (90, 200, 230), "1": FG}
PROMPT = "dev@laptop $ "

SCENES = [
    {"kind": "title", "title": "reportsieve", "sub": "reproduce, dedupe and score\nsecurity reports before a human reads them",
     "say": "This is report sieve, a small open source command line tool for maintainers whose security inbox is "
            "overflowing. It reproduces, dedupes and scores incoming security reports, so a human only reads the ones that matter."},
    {"kind": "bullets", "title": "The problem",
     "bullets": ["curl: report rate ~2x in 2026, ~50 CVEs projected",
                 "OpenSSL: 9 → 108 security inquiries a month",
                 "Node.js: 30+ reports in one month vs 3 a year earlier",
                 "Same bug arrives 3 times, written 3 different ways",
                 "Every one still needs an expert to read it"],
     "say": "A I did not just bring slop. It brought volume. curl's report rate roughly doubled this year. OpenSSL went "
            "from nine security inquiries a month to over a hundred. Node got thirty reports in a month, versus three the "
            "year before. The same bug now arrives three times, written three different ways, and each one still needs an expert."},
    {"kind": "term", "cwd": "EX/tinyhdr",
     "cmds": ["ls reports/ known/", "reportsieve repro reports/r08-uaf-hdr-remove.md --repo . --show"],
     "say": "Here's a demo inbox for a deliberately buggy toy C library: eight reports, plus one advisory we already "
            "published. Report sieve pulls the proof of concept out of each report. Show prints what it would run, "
            "without running anything."},
    {"kind": "term", "cwd": "EX/tinyhdr",
     "cmds": ["reportsieve repro reports/r08-uaf-hdr-remove.md --repo . -v | head -n 8"],
     "say": "Repro runs it in a bubblewrap sandbox: no network, an empty home directory, no tokens in the environment, "
            "and a throwaway copy of the repo. Address sanitizer fires, and we get a crash signature: heap use after free in h d r remove."},
    {"kind": "term", "cwd": "EX/tinyhdr",
     "cmds": ["reportsieve triage reports/ --repo . --repro --color always -q"],
     "say": "Now the whole inbox. Two reports are confirmed by a real crash. The A I written write up is a real bug, so it "
            "isn't thrown away: its proof of concept hits the same crash signature as report one, so it's a duplicate. The "
            "short report is a duplicate by content. One matches our published advisory, one only touches example code, "
            "and the remote code execution claim gets zero. Three of eight need a human."},
    {"kind": "term", "cwd": "EX/tinyhdr",
     "cmds": ["reportsieve brief reports/ --id r05-rce-callback --repo . | head -n 24"],
     "say": "Each report gets a one page brief. This one claims C V S S nine point eight, has no proof of concept, and "
            "cites a function and a file that don't exist anywhere in the repo. The brief lists exactly what to ask the reporter for."},
    {"kind": "term", "cwd": "/tmp/rsdemo",
     "cmds": ["cat req.md", "reportsieve triage req.md --known osv:PyPI/requests --color always --no-history"],
     "say": "Known issue matching works against real data too. Here's a re-report of an old requests bug. Pointed at the "
            "O S V database, report sieve matches it to the published Proxy Authorization advisory."},
    {"kind": "bullets", "title": "What you get",
     "bullets": ["Sandboxed PoC runs: bwrap, docker or podman, no network",
                 "Crash signatures from ASan, UBSan, gdb, Python, JS",
                 "Dedupe + known matching: GitHub advisories, OSV, history",
                 "Evidence score, needs-info questions, one-page briefs",
                 "Text, Markdown, JSON · pure Python, no dependencies"],
     "say": "You get sandboxed proof of concept runs, crash signatures, dedupe against each other, your history, GitHub "
            "advisories and O S V, an evidence score, and briefs in text, markdown or JSON. It's heuristics, not a verdict: "
            "it orders the queue, and a human still decides."},
    {"kind": "bullets", "title": "Try it",
     "bullets": ["curl -fsSL https://raw.githubusercontent.com/",
                 "   hamarshehmhmd/reportsieve/main/install.sh | sh",
                 "reportsieve triage inbox/ --repo . --repro",
                 "github.com/hamarshehmhmd/reportsieve",
                 "GNU AGPL-3.0 (commercial licenses available)"],
     "say": "Install it with the one line installer and point it at your inbox. It's licensed under the GNU A G P L "
            "version three or later, with commercial licenses available from the author. It's on GitHub at "
            "hamarsheh m h m d slash report sieve."},
]


async def tts(text, path):
    import edge_tts
    for attempt in range(8):
        try:
            await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)
            return
        except Exception:
            if os.path.exists(path):
                os.remove(path)
            if attempt == 7:
                raise
            await asyncio.sleep(5)


def duration(path):
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
        text=True,
    )
    return float(out.strip())


EXPORTS = {}


def run_cmd(cmd, cwd):
    if cmd.startswith("export ") and "=" in cmd:
        k, v = cmd[7:].split("=", 1)
        EXPORTS[k] = v
        return ""
    env = dict(os.environ, FORCE_COLOR="1", **EXPORTS)
    env.pop("NO_COLOR", None)
    env["PATH"] = SDKBIN + os.pathsep + env["PATH"]
    env["COLUMNS"] = "120"
    p = subprocess.run(
        ["bash", "-c", "shopt -s nullglob; " + cmd],
        cwd=cwd, capture_output=True, text=True, env=env,
    )
    return (p.stdout + p.stderr).rstrip("\n")


def parse_ansi(line):
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 14)
        self.bold = ImageFont.truetype(MONO_B, 14)
        self.cw = self.font.getlength("M")
        self.lh = 20
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cut = text.rfind(" ", 0, room + 1)
                    cut = cut if cut > 0 else room
                    cur.append((text[:cut], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[cut:].lstrip(" ")
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), "~ — bash", font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-30:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 84), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 34), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/reportsieve  ·  repro · dedupe · score  ·  GNU AGPL-3.0",
               font=ImageFont.truetype(SANS, 22), fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
             "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
             "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
             "-shortest", path],
            stdin=subprocess.PIPE,
        )
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def render_scene(i, scene, workdir):
    workdir = scene.get("cwd", SANDBOX).replace("EX", os.path.join(SANDBOX, "examples"))
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    outputs = [run_cmd(c, workdir) for c in scene["cmds"]]
    # Truncate very long check output so it fits the terminal window
    capped = []
    for out in outputs:
        lines = out.splitlines()
        if len(lines) > 26:
            lines = lines[:24] + ["…", lines[-1]]
        capped.append("\n".join(lines))
    outputs = capped
    steps = list(zip(shown, outputs))
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(PROMPT, (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        hold = min(pause, max(0, total - w.n))
        w.put(t.frame(lines), hold)
    final = t.frame(lines + t.wrap([(PROMPT, (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path


REQ = """Subject: Proxy-Authorization header leaked on redirect to a different host
requests leaks the Proxy-Authorization header to the destination
server after a redirect. Seen on version 2.31.0.
"""


def prepare():
    os.makedirs(BUILD, exist_ok=True)
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX)
    os.makedirs(SANDBOX)
    shutil.copytree(os.path.join(ROOT, "examples"), os.path.join(SANDBOX, "examples"),
                    ignore=shutil.ignore_patterns(".reportsieve"))
    with open(os.path.join(SANDBOX, "req.md"), "w") as fh:
        fh.write(REQ)


def gif():
    """Short silent GIF of the full triage for the README."""
    prepare()
    t = Term()
    cwd = os.path.join(SANDBOX, "examples", "tinyhdr")
    cmd = "reportsieve triage reports/ --repo . --repro --color always -q"
    out = run_cmd(cmd, cwd)
    frames_dir = os.path.join(BUILD, "gif")
    shutil.rmtree(frames_dir, ignore_errors=True)
    os.makedirs(frames_dir)
    imgs = []
    prompt = [(PROMPT, (95, 215, 120), True)]
    for k in range(0, len(cmd) + 1, 3):
        imgs.append((t.frame(t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True), 1))
    lines = t.wrap(prompt + [(cmd, FG, False)])
    imgs.append((t.frame(lines), 8))
    for ol in out.splitlines():
        lines += t.wrap(parse_ansi(ol))
        imgs.append((t.frame(lines), 2))
    imgs.append((t.frame(lines), 60))
    n = 0
    for img, count in imgs:
        for _ in range(count):
            img.resize((960, 540)).save(os.path.join(frames_dir, f"f{n:05d}.png"))
            n += 1
    dst = os.path.join(ROOT, "docs", "demo.gif")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "12", "-i", os.path.join(frames_dir, "f%05d.png"),
                    "-vf", "split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=none", dst], check=True)
    print(dst, os.path.getsize(dst) // 1024, "KB")


def main():
    if "--gif" in sys.argv:
        return gif()
    prepare()
    parts = [render_scene(i, s, SANDBOX) for i, s in enumerate(SCENES)]
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
         os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT],
        check=True,
    )
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
