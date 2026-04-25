#!/usr/bin/env python3
"""Generate Overwatch SIEM branding images to replace Wazuh logos."""
from PIL import Image, ImageDraw, ImageFont
import struct, io, os

# Brand colors
OW_ORANGE_DARK  = (236, 92,  21)   # #EC5C15
OW_ORANGE_MID   = (247, 136, 24)   # #F78818
OW_ORANGE_LIGHT = (252, 186, 15)   # #FCBA0F
OW_TEAL         = (71,  196, 210)  # #47C4D2
OW_TEAL_DARK    = (55,  162, 174)  # darker teal
OW_RED          = (198, 75,  48)   # #C64B30
OW_DARK         = (22,  22,  22)   # #161616
WHITE           = (255, 255, 255)
OW_TEXT_ORANGE  = (224, 74,  22)   # text color


def lerp(a, b, t):
    return int(a + (b - a) * t)


def lerp_color(c1, c2, t):
    return (lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t))


def fill_gradient_horizontal(img, x0, y0, x1, y1, c_left, c_right, clip_mask=None):
    """Fill a region with a horizontal gradient, optionally masked."""
    draw = ImageDraw.Draw(img)
    width = img.width
    for x in range(int(x0), int(x1) + 1):
        if x < 0 or x >= width:
            continue
        t = (x - x0) / max(x1 - x0, 1)
        color = lerp_color(c_left, c_right, t)
        draw.line([(x, int(y0)), (x, int(y1))], fill=color)


def polygon_mask(size, points):
    """Return a mask Image where the polygon is white."""
    mask = Image.new('L', size, 0)
    ImageDraw.Draw(mask).polygon(points, fill=255)
    return mask


def draw_overwatch_icon(canvas, ox, oy, size, bg_color=WHITE):
    """
    Draw the Overwatch SIEM icon at offset (ox, oy) with given logical size.
    bg_color is the background to reveal in the inner cut-out areas.
    """
    draw = ImageDraw.Draw(canvas)
    s = size

    # ── Outer chevron shape (orange gradient) ──────────────────────────────
    # Two overlapping ">" shapes fused into a single polygon that looks like >>
    # Coordinates relative to icon center (cx, cy)
    cx = ox + s * 0.50
    cy = oy + s * 0.52

    # Outer silhouette: a right-pointing arrow/chevron
    outer = [
        (cx - s*0.80, cy - s*0.30),   # left top
        (cx - s*0.80, cy + s*0.30),   # left bottom
        (cx - s*0.35, cy + s*0.52),   # lower mid-left
        (cx + s*0.40, cy + s*0.52),   # lower mid-right
        (cx + s*0.68, cy),            # right tip
        (cx + s*0.40, cy - s*0.52),   # upper mid-right
        (cx - s*0.35, cy - s*0.52),   # upper mid-left
    ]

    # Draw gradient onto a temp layer then paste using polygon mask
    layer = Image.new('RGB', canvas.size, bg_color)
    fill_gradient_horizontal(layer, cx - s*0.80, cy - s*0.52,
                              cx + s*0.68, cy + s*0.52,
                              OW_ORANGE_DARK, OW_ORANGE_LIGHT)
    mask = polygon_mask(canvas.size, [(int(p[0]), int(p[1])) for p in outer])
    canvas.paste(layer, mask=mask)

    # ── Inner left chevron cut-out (reveals bg) ─────────────────────────────
    inner_left = [
        (cx - s*0.72, cy - s*0.22),
        (cx - s*0.72, cy + s*0.22),
        (cx - s*0.30, cy + s*0.44),
        (cx - s*0.08, cy + s*0.44),
        (cx - s*0.42, cy),
        (cx - s*0.08, cy - s*0.44),
        (cx - s*0.30, cy - s*0.44),
    ]
    draw.polygon([(int(p[0]), int(p[1])) for p in inner_left], fill=bg_color)

    # ── Right chevron darker layer ───────────────────────────────────────────
    # The right chevron is a darker shade to give depth
    right_chev = [
        (cx - s*0.08, cy - s*0.44),
        (cx + s*0.40, cy - s*0.44),
        (cx + s*0.62, cy),
        (cx + s*0.40, cy + s*0.44),
        (cx - s*0.08, cy + s*0.44),
        (cx + s*0.22, cy),
    ]
    # Still orange gradient but slightly darker
    layer2 = Image.new('RGB', canvas.size, bg_color)
    fill_gradient_horizontal(layer2, cx - s*0.08, cy - s*0.44,
                              cx + s*0.62, cy + s*0.44,
                              OW_ORANGE_MID, OW_ORANGE_LIGHT)
    mask2 = polygon_mask(canvas.size, [(int(p[0]), int(p[1])) for p in right_chev])
    canvas.paste(layer2, mask=mask2)

    # ── Inner right cut-out ──────────────────────────────────────────────────
    inner_right = [
        (cx - s*0.02, cy - s*0.36),
        (cx + s*0.38, cy - s*0.36),
        (cx + s*0.54, cy),
        (cx + s*0.38, cy + s*0.36),
        (cx - s*0.02, cy + s*0.36),
        (cx + s*0.22, cy),
    ]
    draw.polygon([(int(p[0]), int(p[1])) for p in inner_right], fill=bg_color)

    # ── Teal diamond with keyhole ────────────────────────────────────────────
    d = s * 0.22
    dcx = cx + s * 0.08
    dcy = cy
    teal_pts = [
        (dcx,         dcy - d),
        (dcx + d*0.8, dcy),
        (dcx,         dcy + d),
        (dcx - d*0.8, dcy),
    ]
    draw.polygon([(int(p[0]), int(p[1])) for p in teal_pts], fill=OW_TEAL)

    # Keyhole: circle + rectangle
    kr = d * 0.32
    kx, ky = dcx, dcy - kr * 0.2
    draw.ellipse([int(kx-kr), int(ky-kr), int(kx+kr), int(ky+kr)], fill=WHITE)
    rect_w = kr * 0.62
    draw.rectangle([int(kx-rect_w), int(ky), int(kx+rect_w), int(ky+kr*1.1)], fill=WHITE)
    # Cut hole in circle
    cr = kr * 0.42
    draw.ellipse([int(kx-cr), int(ky-cr), int(kx+cr), int(ky+cr)], fill=OW_TEAL)

    # ── Small decorative diamonds ────────────────────────────────────────────
    def mini_diamond(x, y, r, color):
        pts = [(int(x), int(y-r)), (int(x+r), int(y)), (int(x), int(y+r)), (int(x-r), int(y))]
        draw.polygon(pts, fill=color)

    dm = s * 0.055
    mini_diamond(cx - s*0.50, cy - s*0.42, dm*0.75, OW_TEAL)
    mini_diamond(cx - s*0.25, cy - s*0.56, dm,       OW_ORANGE_LIGHT)
    mini_diamond(cx + s*0.02, cy - s*0.50, dm*0.80,  OW_RED)
    mini_diamond(cx - s*0.44, cy - s*0.28, dm*0.70,  OW_RED)

    # ── Circuit board traces (bottom-right inner area) ───────────────────────
    trace_color = WHITE
    tw = max(1, int(s * 0.025))
    tr = tw * 2

    # Three angled lines from left to right
    base_x = cx + s*0.02
    base_y = cy + s*0.12
    end_x  = cx + s*0.44
    for i, dy in enumerate([s*0.06, s*0.16, s*0.26]):
        y1 = base_y + dy
        y2 = base_y + dy + s*0.10
        if y2 > dcy + d + s*0.05:  # stay within chevron bounds roughly
            break
        draw.line([(int(base_x), int(y1)), (int(end_x), int(y2))],
                  fill=trace_color, width=tw)
        draw.ellipse([int(base_x-tr), int(y1-tr), int(base_x+tr), int(y1+tr)],
                     fill=trace_color)
        draw.ellipse([int(end_x-tr), int(y2-tr), int(end_x+tr), int(y2+tr)],
                     fill=trace_color)


def get_font(size):
    """Try to get a bold font, fall back to default."""
    for path in [
        '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
        '/usr/share/fonts/truetype/freefont/FreeSansBold.ttf',
        '/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf',
    ]:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


# ─────────────────────────────────────────────────────────────────────────────
# 1. bannrbmp.jpg  (493×58 PNG – installer top banner)
# ─────────────────────────────────────────────────────────────────────────────
def make_banner():
    W, H = 493, 58
    img = Image.new('RGB', (W, H), WHITE)
    draw = ImageDraw.Draw(img)

    # Orange accent bar at top
    draw.rectangle([0, 0, W, 3], fill=OW_ORANGE_DARK)

    # Draw icon on the left
    icon_size = 44
    draw_overwatch_icon(img, 6, 7, icon_size, bg_color=WHITE)

    # "overwatch" text
    font_large = get_font(22)
    font_small = get_font(11)
    text = "overwatch"
    try:
        bbox = draw.textbbox((0, 0), text, font=font_large)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    except AttributeError:
        tw, th = draw.textsize(text, font=font_large)

    tx = W - tw - 12
    ty = (H - th) // 2 - 1
    draw.text((tx, ty), text, fill=OW_TEXT_ORANGE, font=font_large)

    # Subtitle
    sub = "SIEM"
    try:
        bbox2 = draw.textbbox((0, 0), sub, font=font_small)
        sw = bbox2[2] - bbox2[0]
    except AttributeError:
        sw, _ = draw.textsize(sub, font=font_small)
    draw.text((W - sw - 13, ty + th + 1), sub, fill=OW_ORANGE_MID, font=font_small)

    img.save('/home/user/overwatch-siem/src/win32/ui/bannrbmp.jpg', format='PNG')
    print("bannrbmp.jpg → done")


# ─────────────────────────────────────────────────────────────────────────────
# 2. dlgbmp.jpg  (493×312 JPEG – installer dialog left panel)
# ─────────────────────────────────────────────────────────────────────────────
def make_dialog():
    W, H = 493, 312
    PANEL_W = 163   # dark left panel width
    img = Image.new('RGB', (W, H), WHITE)
    draw = ImageDraw.Draw(img)

    # Left panel gradient (dark orange to very dark)
    for x in range(PANEL_W):
        t = x / PANEL_W
        color = lerp_color(OW_DARK, (60, 30, 5), t)
        draw.line([(x, 0), (x, H)], fill=color)

    # Orange accent line on right edge of left panel
    draw.rectangle([PANEL_W - 3, 0, PANEL_W, H], fill=OW_ORANGE_DARK)

    # Draw icon centered in left panel
    icon_size = 100
    icon_ox = (PANEL_W - icon_size) // 2
    icon_oy = (H // 2 - icon_size // 2) - 20
    draw_overwatch_icon(img, icon_ox, icon_oy, icon_size, bg_color=OW_DARK)

    # "overwatch" text below icon
    font_name = get_font(18)
    font_siem = get_font(11)
    try:
        bbox = ImageDraw.Draw(img).textbbox((0, 0), "overwatch", font=font_name)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
    except AttributeError:
        tw, th = 80, 18

    tx = (PANEL_W - tw) // 2
    ty = icon_oy + icon_size + 10
    draw.text((tx, ty), "overwatch", fill=OW_ORANGE_LIGHT, font=font_name)

    try:
        bbox2 = ImageDraw.Draw(img).textbbox((0, 0), "SIEM", font=font_siem)
        sw = bbox2[2] - bbox2[0]
    except AttributeError:
        sw = 30
    draw.text(((PANEL_W - sw) // 2, ty + th + 3), "SIEM",
              fill=OW_TEAL, font=font_siem)

    img.save('/home/user/overwatch-siem/src/win32/ui/dlgbmp.jpg', format='JPEG', quality=95)
    print("dlgbmp.jpg → done")


# ─────────────────────────────────────────────────────────────────────────────
# 3. favicon.ico  (32×32 and 64×64)
# ─────────────────────────────────────────────────────────────────────────────
def make_ico_frame(size):
    """Return an RGBA Image with the icon at given size."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Orange background circle/rounded square
    pad = size * 0.04
    draw.ellipse([int(pad), int(pad), int(size - pad), int(size - pad)],
                 fill=OW_ORANGE_MID)

    # Draw mini icon
    icon_pad = size * 0.10
    draw_overwatch_icon(img, int(icon_pad), int(icon_pad),
                        int(size - 2 * icon_pad), bg_color=OW_ORANGE_MID)
    return img


def make_ico(path):
    frames = [make_ico_frame(s) for s in [16, 32, 48]]
    frames[0].save(path, format='ICO', sizes=[(16, 16), (32, 32), (48, 48)],
                   append_images=frames[1:])
    print(f"{path} → done")


# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    make_banner()
    make_dialog()
    make_ico('/home/user/overwatch-siem/src/win32/favicon.ico')
    make_ico('/home/user/overwatch-siem/src/win32/ui/favicon.ico')
    # install.ico is larger (64×64)
    big = make_ico_frame(64)
    big.save('/home/user/overwatch-siem/src/win32/install.ico', format='ICO',
             sizes=[(64, 64)])
    print("install.ico → done")
    # uninstall.ico
    big.save('/home/user/overwatch-siem/src/win32/uninstall.ico', format='ICO',
             sizes=[(64, 64)])
    print("uninstall.ico → done")
    print("All done!")
