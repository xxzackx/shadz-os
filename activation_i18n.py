"""Activation Engine v1 Hotfix H1F — Multilingual Activation Flow.

Translation data and lookup helpers for the Telegram activation flow
(bot_runtime.py). Scope is locked to the activation flow only — no other
SHADZ OS module (self-service management, Admin Panel, etc.) is touched.

Supported languages (exactly these 4, per the corrected H1F spec):
  en (English), km (Khmer), id (Indonesian), zh-Hans (Simplified Chinese).

Every MESSAGES/BUTTONS entry has a complete "en" translation — text()/
button() fall back to "en" for a missing/unknown language code, so a
malformed or stale session["language"] (or one predating this hotfix) can
never crash or emit an empty string, only render in English.
"""

DEFAULT_LANGUAGE = "en"

# Ordered (code, native display label) — the order buttons are rendered in.
SUPPORTED_LANGUAGES = [
    ("en", "English"),
    ("km", "ខ្មែរ"),
    ("id", "Bahasa Indonesia"),
    ("zh-Hans", "简体中文"),
]

LANGUAGE_CODES = frozenset(code for code, _ in SUPPORTED_LANGUAGES)

MESSAGES = {
    "ENTRY": {
        "en": (
            "✨ Your SHADZ product is ready to activate.\n\n"
            "Activate it now to connect this product to your account and unlock "
            "self-service management."
        ),
        "km": (
            "✨ ផលិតផល SHADZ របស់អ្នករួចរាល់សម្រាប់ការធ្វើឱ្យសកម្មហើយ។\n\n"
            "ធ្វើឱ្យសកម្មឥឡូវនេះ ដើម្បីភ្ជាប់ផលិតផលនេះទៅគណនីរបស់អ្នក "
            "និងដោះសោការគ្រប់គ្រងដោយខ្លួនឯង។"
        ),
        "id": (
            "✨ Produk SHADZ Anda siap diaktifkan.\n\n"
            "Aktifkan sekarang untuk menghubungkan produk ini ke akun Anda dan "
            "membuka pengelolaan mandiri (self-service)."
        ),
        "zh-Hans": (
            "✨ 您的 SHADZ 产品已可激活。\n\n"
            "立即激活以将此产品关联到您的账户，并解锁自助管理功能。"
        ),
    },
    "CALLBACK_INVALID": {
        "en": "This activation link is no longer valid.",
        "km": "តំណភ្ជាប់ធ្វើឱ្យសកម្មនេះលែងមានសុពលភាពទៀតហើយ។",
        "id": "Tautan aktivasi ini sudah tidak berlaku lagi.",
        "zh-Hans": "此激活链接已失效。",
    },
    "INVALID_LINK": {
        "en": (
            "This activation link is invalid or no longer available. Please scan "
            "your SHADZ product again or contact SHADZ support."
        ),
        "km": (
            "តំណភ្ជាប់ធ្វើឱ្យសកម្មនេះមិនត្រឹមត្រូវ ឬលែងមានទៀតហើយ។ សូមស្កេនផលិតផល "
            "SHADZ របស់អ្នកម្តងទៀត ឬទាក់ទងផ្នែកគាំទ្រ SHADZ។"
        ),
        "id": (
            "Tautan aktivasi ini tidak valid atau sudah tidak tersedia. Silakan "
            "pindai ulang produk SHADZ Anda atau hubungi dukungan SHADZ."
        ),
        "zh-Hans": (
            "此激活链接无效或已不可用。请重新扫描您的 SHADZ 产品，或联系 SHADZ 客服。"
        ),
    },
    "CONFIRMATION_REMINDER": {
        "en": 'Please tap "Activate Now" to continue activating your SHADZ product.',
        "km": 'សូមចុច "ធ្វើឱ្យសកម្មឥឡូវនេះ" ដើម្បីបន្តការធ្វើឱ្យសកម្មផលិតផល SHADZ របស់អ្នក។',
        "id": 'Silakan ketuk "Aktifkan Sekarang" untuk melanjutkan mengaktifkan produk SHADZ Anda.',
        "zh-Hans": "请点击“立即激活”以继续激活您的 SHADZ 产品。",
    },
    "ACCESS_CODE_READY": {
        "en": (
            "Your SHADZ client access is ready.\n\n"
            "Access code: {code}\n\n"
            "We'll continue setting up your product next."
        ),
        "km": (
            "ការចូលប្រើជាអតិថិជន SHADZ របស់អ្នករួចរាល់ហើយ។\n\n"
            "លេខកូដចូលប្រើ៖ {code}\n\n"
            "បន្ទាប់មកយើងនឹងបន្តរៀបចំផលិតផលរបស់អ្នក។"
        ),
        "id": (
            "Akses klien SHADZ Anda sudah siap.\n\n"
            "Kode akses: {code}\n\n"
            "Selanjutnya kami akan melanjutkan penyiapan produk Anda."
        ),
        "zh-Hans": (
            "您的 SHADZ 客户访问权限已就绪。\n\n"
            "访问码：{code}\n\n"
            "接下来我们将继续设置您的产品。"
        ),
    },
    "MISSING_IDENTITY": {
        "en": (
            "We couldn't verify your Telegram account. Please try again from your "
            "SHADZ product link, or contact SHADZ support."
        ),
        "km": (
            "យើងមិនអាចផ្ទៀងផ្ទាត់គណនី Telegram របស់អ្នកបានទេ។ សូមព្យាយាមម្តងទៀត"
            "ពីតំណភ្ជាប់ផលិតផល SHADZ របស់អ្នក ឬទាក់ទងផ្នែកគាំទ្រ SHADZ។"
        ),
        "id": (
            "Kami tidak dapat memverifikasi akun Telegram Anda. Silakan coba lagi "
            "melalui tautan produk SHADZ Anda, atau hubungi dukungan SHADZ."
        ),
        "zh-Hans": (
            "我们无法验证您的 Telegram 账户。请通过您的 SHADZ 产品链接重试，或联系 SHADZ 客服。"
        ),
    },
    "CLIENT_BLOCKED": {
        "en": "We couldn't complete this step right now. Please contact SHADZ support.",
        "km": "យើងមិនអាចបញ្ចប់ជំហាននេះបានទេនៅពេលនេះ។ សូមទាក់ទងផ្នែកគាំទ្រ SHADZ។",
        "id": "Kami tidak dapat menyelesaikan langkah ini saat ini. Silakan hubungi dukungan SHADZ.",
        "zh-Hans": "目前无法完成此步骤。请联系 SHADZ 客服。",
    },
    "URL_PROMPT": {
        "en": (
            "Now let's set up your destination.\n\n"
            "Reply with the destination URL for this product — a domain such as "
            "example.com or a full http:// / https:// URL."
        ),
        "km": (
            "ឥឡូវនេះសូមរៀបចំទិសដៅរបស់អ្នក។\n\n"
            "ឆ្លើយតបជាមួយ URL ទិសដៅសម្រាប់ផលិតផលនេះ — ដូចជាដែន example.com ឬ "
            "URL ពេញលេញ http:// / https://។"
        ),
        "id": (
            "Sekarang mari siapkan tujuan Anda.\n\n"
            "Balas dengan URL tujuan untuk produk ini — domain seperti example.com "
            "atau URL lengkap http:// / https://."
        ),
        "zh-Hans": (
            "现在让我们设置您的目的地。\n\n"
            "请回复此产品的目的地网址——例如 example.com 这样的域名，"
            "或完整的 http:// / https:// 网址。"
        ),
    },
    "URL_INVALID_FORMAT": {
        "en": (
            "That doesn't look like a valid web URL. Send a domain such as "
            "example.com or a full http:// / https:// URL, then try again."
        ),
        "km": (
            "នោះមើលទៅមិនមែនជា URL គេហទំព័រត្រឹមត្រូវទេ។ សូមផ្ញើដែនដូចជា example.com "
            "ឬ URL ពេញលេញ http:// / https:// រួចព្យាយាមម្តងទៀត។"
        ),
        "id": (
            "Itu sepertinya bukan URL web yang valid. Kirim domain seperti "
            "example.com atau URL lengkap http:// / https://, lalu coba lagi."
        ),
        "zh-Hans": (
            "这看起来不是有效的网址。请发送例如 example.com 的域名，"
            "或完整的 http:// / https:// 网址，然后重试。"
        ),
    },
    "URL_BLOCKED": {
        "en": (
            "This link cannot be used because it points back to SHADZ or an "
            "internal address. Please send an external public link instead."
        ),
        "km": (
            "តំណភ្ជាប់នេះមិនអាចប្រើបានទេ ព្រោះវាចង្អុលទៅ SHADZ ឬអាសយដ្ឋានផ្ទៃក្នុង។ "
            "សូមផ្ញើតំណភ្ជាប់សាធារណៈខាងក្រៅ។"
        ),
        "id": (
            "Tautan ini tidak dapat digunakan karena mengarah kembali ke SHADZ "
            "atau alamat internal. Silakan kirim tautan publik eksternal."
        ),
        "zh-Hans": "此链接无法使用，因为它指向 SHADZ 或内部地址。请发送外部公开链接。",
    },
    "URL_CONFIRM_PROMPT": {
        "en": (
            "Confirm destination:\n{url}\n\n"
            "Tap Confirm to save it, or Change URL to send a different one."
        ),
        "km": "បញ្ជាក់ទិសដៅ៖\n{url}\n\nចុច បញ្ជាក់ ដើម្បីរក្សាទុក ឬ ប្តូរ URL ដើម្បីផ្ញើមួយផ្សេង។",
        "id": "Konfirmasi tujuan:\n{url}\n\nKetuk Konfirmasi untuk menyimpannya, atau Ubah URL untuk mengirim yang berbeda.",
        "zh-Hans": "确认目的地：\n{url}\n\n点击“确认”以保存，或点击“更改网址”以发送其他网址。",
    },
    "URL_CONFIRM_INVALID_REPLY": {
        "en": (
            "Please tap Confirm or Change URL above, or reply YES to confirm or NO "
            "to send a different URL."
        ),
        "km": "សូមចុច បញ្ជាក់ ឬ ប្តូរ URL ខាងលើ ឬឆ្លើយតប YES ដើម្បីបញ្ជាក់ ឬ NO ដើម្បីផ្ញើ URL ផ្សេង។",
        "id": "Silakan ketuk Konfirmasi atau Ubah URL di atas, atau balas YES untuk mengonfirmasi atau NO untuk mengirim URL berbeda.",
        "zh-Hans": "请点击上方的“确认”或“更改网址”，或回复 YES 确认，或回复 NO 发送其他网址。",
    },
    "URL_RETRY": {
        "en": "No problem — please send the destination URL again.",
        "km": "មិនអីទេ — សូមផ្ញើ URL ទិសដៅម្តងទៀត។",
        "id": "Tidak masalah — silakan kirim ulang URL tujuan.",
        "zh-Hans": "没问题——请再次发送目的地网址。",
    },
    "URL_SAVED": {
        "en": (
            "Got it. Destination saved for setup:\n{url}\n\n"
            "We'll continue setting up your product next."
        ),
        "km": "យល់ព្រម។ ទិសដៅត្រូវបានរក្សាទុកសម្រាប់ការរៀបចំ៖\n{url}\n\nបន្ទាប់មកយើងនឹងបន្តរៀបចំផលិតផលរបស់អ្នក។",
        "id": "Baik. Tujuan disimpan untuk penyiapan:\n{url}\n\nSelanjutnya kami akan melanjutkan penyiapan produk Anda.",
        "zh-Hans": "已收到。用于设置的目的地已保存：\n{url}\n\n接下来我们将继续设置您的产品。",
    },
    "MEDIA_PROMPT": {
        "en": (
            "Now let's set up your media.\n\n"
            "Send a photo, document, video, or GIF for this product."
        ),
        "km": "ឥឡូវនេះសូមរៀបចំមេឌៀរបស់អ្នក។\n\nផ្ញើរូបថត ឯកសារ វីដេអូ ឬ GIF សម្រាប់ផលិតផលនេះ។",
        "id": "Sekarang mari siapkan media Anda.\n\nKirim foto, dokumen, video, atau GIF untuk produk ini.",
        "zh-Hans": "现在让我们设置您的媒体。\n\n请发送此产品的照片、文件、视频或 GIF。",
    },
    "MEDIA_UNSUPPORTED": {
        "en": (
            "Please send a photo, document, video, or GIF to set up the media — "
            "plain text isn't accepted."
        ),
        "km": "សូមផ្ញើរូបថត ឯកសារ វីដេអូ ឬ GIF ដើម្បីរៀបចំមេឌៀ — អត្ថបទធម្មតាមិនត្រូវបានទទួលយកទេ។",
        "id": "Silakan kirim foto, dokumen, video, atau GIF untuk menyiapkan media — teks biasa tidak diterima.",
        "zh-Hans": "请发送照片、文件、视频或 GIF 以设置媒体——不接受纯文本。",
    },
    "MEDIA_UNSUPPORTED_TYPE": {
        "en": (
            "That file type ({mime}) isn't supported. "
            "Supported: JPEG/PNG/WEBP images, MP4/QuickTime/WEBM video, GIF."
        ),
        "km": "ប្រភេទឯកសារនោះ ({mime}) មិនត្រូវបានគាំទ្រទេ។ ត្រូវបានគាំទ្រ៖ រូបភាព JPEG/PNG/WEBP វីដេអូ MP4/QuickTime/WEBM និង GIF។",
        "id": "Jenis file itu ({mime}) tidak didukung. Didukung: gambar JPEG/PNG/WEBP, video MP4/QuickTime/WEBM, GIF.",
        "zh-Hans": "不支持该文件类型（{mime}）。支持格式：JPEG/PNG/WEBP 图片、MP4/QuickTime/WEBM 视频、GIF。",
    },
    "MEDIA_TOO_LARGE": {
        "en": "That file is too large ({size} MB). Max supported size is {max} MB.",
        "km": "ឯកសារនោះធំពេក ({size} MB)។ ទំហំអតិបរមាដែលគាំទ្រគឺ {max} MB។",
        "id": "File itu terlalu besar ({size} MB). Ukuran maksimum yang didukung adalah {max} MB.",
        "zh-Hans": "文件过大（{size} MB）。最大支持大小为 {max} MB。",
    },
    "MEDIA_CONFIRM_PROMPT": {
        "en": (
            "Confirm media:\n{name}\n\n"
            "Tap Confirm to save it, or Change Media to send a different file."
        ),
        "km": "បញ្ជាក់មេឌៀ៖\n{name}\n\nចុច បញ្ជាក់ ដើម្បីរក្សាទុក ឬ ប្តូរមេឌៀ ដើម្បីផ្ញើឯកសារផ្សេង។",
        "id": "Konfirmasi media:\n{name}\n\nKetuk Konfirmasi untuk menyimpannya, atau Ubah Media untuk mengirim file berbeda.",
        "zh-Hans": "确认媒体：\n{name}\n\n点击“确认”以保存，或点击“更改媒体”以发送其他文件。",
    },
    "MEDIA_CONFIRM_REMINDER": {
        "en": 'Please tap "Confirm" or "Change Media" above to continue.',
        "km": 'សូមចុច "បញ្ជាក់" ឬ "ប្តូរមេឌៀ" ខាងលើដើម្បីបន្ត។',
        "id": 'Silakan ketuk "Konfirmasi" atau "Ubah Media" di atas untuk melanjutkan.',
        "zh-Hans": "请点击上方的“确认”或“更改媒体”以继续。",
    },
    "MEDIA_RETRY": {
        "en": "No problem — please send the media again.",
        "km": "មិនអីទេ — សូមផ្ញើមេឌៀម្តងទៀត។",
        "id": "Tidak masalah — silakan kirim ulang media.",
        "zh-Hans": "没问题——请再次发送媒体。",
    },
    "MEDIA_SAVED": {
        "en": (
            "Got it. Media saved for setup.\n\n"
            "We'll continue setting up your product next."
        ),
        "km": "យល់ព្រម។ មេឌៀត្រូវបានរក្សាទុកសម្រាប់ការរៀបចំ។\n\nបន្ទាប់មកយើងនឹងបន្តរៀបចំផលិតផលរបស់អ្នក។",
        "id": "Baik. Media disimpan untuk penyiapan.\n\nSelanjutnya kami akan melanjutkan penyiapan produk Anda.",
        "zh-Hans": "已收到。媒体已保存以供设置使用。\n\n接下来我们将继续设置您的产品。",
    },
    "FINALIZE_FAILED": {
        "en": "Something went wrong completing activation. Please try again in a moment.",
        "km": "មានបញ្ហាកើតឡើងក្នុងការបញ្ចប់ការធ្វើឱ្យសកម្ម។ សូមព្យាយាមម្តងទៀតក្នុងពេលឆាប់ៗនេះ។",
        "id": "Terjadi kesalahan saat menyelesaikan aktivasi. Silakan coba lagi sesaat lagi.",
        "zh-Hans": "完成激活时出现问题。请稍后再试。",
    },
    "ASSIGNMENT_CONFLICT": {
        "en": "This product can't be activated right now. Please contact SHADZ support.",
        "km": "ផលិតផលនេះមិនអាចធ្វើឱ្យសកម្មបានទេនៅពេលនេះ។ សូមទាក់ទងផ្នែកគាំទ្រ SHADZ។",
        "id": "Produk ini tidak dapat diaktifkan saat ini. Silakan hubungi dukungan SHADZ.",
        "zh-Hans": "此产品目前无法激活。请联系 SHADZ 客服。",
    },
    "FINALIZE_RETRY_URL": {
        "en": "Please tap Confirm above, or reply YES, to finish activating your product.",
        "km": "សូមចុច បញ្ជាក់ ខាងលើ ឬឆ្លើយតប YES ដើម្បីបញ្ចប់ការធ្វើឱ្យសកម្មផលិតផលរបស់អ្នក។",
        "id": "Silakan ketuk Konfirmasi di atas, atau balas YES, untuk menyelesaikan aktivasi produk Anda.",
        "zh-Hans": "请点击上方的“确认”，或回复 YES，以完成激活您的产品。",
    },
    "FINALIZE_RETRY_MEDIA": {
        "en": "Please tap Confirm above to finish activating your product.",
        "km": "សូមចុច បញ្ជាក់ ខាងលើដើម្បីបញ្ចប់ការធ្វើឱ្យសកម្មផលិតផលរបស់អ្នក។",
        "id": "Silakan ketuk Konfirmasi di atas untuk menyelesaikan aktivasi produk Anda.",
        "zh-Hans": "请点击上方的“确认”以完成激活您的产品。",
    },
    "COMPLETE": {
        "en": (
            "Activation completed. Your SHADZ product is now active.\n\n"
            "Access code: {code}\n\n"
            "Use your code any time to manage this product."
        ),
        "km": "ការធ្វើឱ្យសកម្មបានបញ្ចប់។ ផលិតផល SHADZ របស់អ្នកឥឡូវនេះសកម្មហើយ។\n\nលេខកូដចូលប្រើ៖ {code}\n\nប្រើលេខកូដរបស់អ្នកគ្រប់ពេលដើម្បីគ្រប់គ្រងផលិតផលនេះ។",
        "id": "Aktivasi selesai. Produk SHADZ Anda sekarang aktif.\n\nKode akses: {code}\n\nGunakan kode Anda kapan saja untuk mengelola produk ini.",
        "zh-Hans": "激活完成。您的 SHADZ 产品现已激活。\n\n访问码：{code}\n\n您可随时使用此访问码来管理此产品。",
    },
    "LANGUAGE_PROMPT": {
        "en": "Please select your language:",
    },
}

BUTTONS = {
    "ACTIVATE_NOW": {
        "en": "Activate Now",
        "km": "ធ្វើឱ្យសកម្មឥឡូវនេះ",
        "id": "Aktifkan Sekarang",
        "zh-Hans": "立即激活",
    },
    "CONFIRM": {
        "en": "Confirm",
        "km": "បញ្ជាក់",
        "id": "Konfirmasi",
        "zh-Hans": "确认",
    },
    "CHANGE_URL": {
        "en": "Change URL",
        "km": "ប្តូរ URL",
        "id": "Ubah URL",
        "zh-Hans": "更改网址",
    },
    "CHANGE_MEDIA": {
        "en": "Change Media",
        "km": "ប្តូរមេឌៀ",
        "id": "Ubah Media",
        "zh-Hans": "更改媒体",
    },
}


def text(key: str, lang: str | None, **fmt) -> str:
    """Look up MESSAGES[key][lang], falling back to English for a missing
    key or an unrecognised/None language code — never raises, never
    returns an empty string for a known key."""
    translations = MESSAGES[key]
    template = translations.get(lang) or translations[DEFAULT_LANGUAGE]
    return template.format(**fmt) if fmt else template


def button(key: str, lang: str | None) -> str:
    """Look up BUTTONS[key][lang], falling back to English — mirrors text()."""
    translations = BUTTONS[key]
    return translations.get(lang) or translations[DEFAULT_LANGUAGE]
