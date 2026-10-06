"""
Theme configuration, color palette, and typography for Document Guardian.
Strict adherence to professional public-service / government-portal design:
Restrained navy, accessible contrast, information-first hierarchy, zero flashy effects.
"""

# Font Definitions (System fonts prioritizing Segoe UI / SF Pro / Inter)
FONT_FAMILY = "Segoe UI"
FONT_TITLE = (FONT_FAMILY, 20, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 14, "bold")
FONT_SECTION = (FONT_FAMILY, 13, "bold")
FONT_BODY = (FONT_FAMILY, 11)
FONT_BODY_BOLD = (FONT_FAMILY, 11, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MONO = ("Consolas", 10)

# Modern Cybersecurity / Personal Privacy Color Palette (Light mode, Dark mode)
COLOR_PRIMARY = ("#2563EB", "#3B82F6")        # Electric Sapphire Blue
COLOR_PRIMARY_HOVER = ("#1D4ED8", "#2563EB")  # Deep Sapphire Blue
COLOR_SECONDARY = ("#475569", "#64748B")      # Modern Slate
COLOR_SECONDARY_HOVER = ("#334155", "#475569")

# Backgrounds and Surfaces
COLOR_BG = ("#F8FAFC", "#0B1120")             # Clean off-white / Deep Cyber Obsidian
COLOR_SURFACE = ("#FFFFFF", "#131C31")        # Crisp white / Sleek dark card
COLOR_SURFACE_ELEVATED = ("#F1F5F9", "#1E2A47") # Elevated card / Hover surface
COLOR_BORDER = ("#E2E8F0", "#243456")         # Refined micro-border
COLOR_HEADER_BG = ("#0F172A", "#080D1A")      # Top bar obsidian
COLOR_DISCLAIMER_BG = ("#EFF6FF", "#172554")  # Refined security info pill
COLOR_DISCLAIMER_TEXT = ("#1E40AF", "#93C5FD")

# Semantic Status Colors (Vibrant & Accessible)
COLOR_STATUS_VALID = ("#059669", "#10B981")       # Emerald green
COLOR_STATUS_VALID_BG = ("#ECFDF5", "#064E3B")
COLOR_STATUS_ATTENTION = ("#D97706", "#F59E0B")   # Amber warning
COLOR_STATUS_ATTENTION_BG = ("#FFFBEB", "#78350F")
COLOR_STATUS_EXPIRED = ("#DC2626", "#EF4444")     # Rose red
COLOR_STATUS_EXPIRED_BG = ("#FEF2F2", "#7F1D1D")
COLOR_STATUS_REVIEW = ("#4F46E5", "#818CF8")      # Indigo review
COLOR_STATUS_REVIEW_BG = ("#EEF2FF", "#312E81")

# Text Colors
COLOR_TEXT_PRIMARY = ("#0F172A", "#F8FAFC")
COLOR_TEXT_SECONDARY = ("#64748B", "#94A3B8")
COLOR_TEXT_MUTED = ("#94A3B8", "#64748B")

# Standard Dimensions (Modern rounded styling)
CORNER_RADIUS_FORMAL = 10  # Modern rounded corner radius for cards, buttons, inputs
CORNER_RADIUS_CARD = 12
CORNER_RADIUS_PILL = 20
BORDER_WIDTH_FORMAL = 1

DISCLAIMER_TEXT = (
    "STUDENT ACADEMIC PROJECT - NOT AN OFFICIAL GOVERNMENT SERVICE. "
    "NO GOVERNMENT AFFILIATION OR ENDORSEMENT."
)
