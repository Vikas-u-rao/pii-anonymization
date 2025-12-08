"""
Custom PII Recognizers for Indian Context.
Includes recognizers for PAN Card, Aadhaar, Indian Phone Numbers, etc.
"""

from presidio_analyzer import Pattern, PatternRecognizer
from typing import List


class IndianPANRecognizer(PatternRecognizer):
    """
    Recognizer for Indian PAN (Permanent Account Number) Card.
    
    PAN Format: AAAAA9999A
    - First 5 characters: Uppercase letters
    - Next 4 characters: Digits (0-9)
    - Last character: Uppercase letter
    
    The 4th character indicates the type of holder:
    - P: Individual
    - C: Company
    - H: HUF (Hindu Undivided Family)
    - F: Firm
    - A: AOP (Association of Persons)
    - T: Trust
    - B: BOI (Body of Individuals)
    - L: Local Authority
    - J: Artificial Juridical Person
    - G: Government
    """
    
    PATTERNS = [
        Pattern(
            name="indian_pan_pattern",
            regex=r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b",
            score=0.85,
        ),
        # Looser pattern with lower confidence
        Pattern(
            name="indian_pan_pattern_loose",
            regex=r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b",
            score=0.6,
        ),
    ]
    
    CONTEXT_WORDS = [
        "pan", "pan card", "pan number", "permanent account number",
        "income tax", "tax id", "pan no", "pan#"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_PAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianAadhaarRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Aadhaar Number.
    
    Aadhaar Format: 12-digit number
    - Can be written as: XXXX XXXX XXXX or XXXX-XXXX-XXXX or XXXXXXXXXXXX
    - First digit cannot be 0 or 1
    - Verhoeff checksum validation (not implemented here for performance)
    """
    
    PATTERNS = [
        # Format: XXXX XXXX XXXX (with spaces)
        Pattern(
            name="aadhaar_spaced",
            regex=r"\b[2-9][0-9]{3}\s[0-9]{4}\s[0-9]{4}\b",
            score=0.85,
        ),
        # Format: XXXX-XXXX-XXXX (with dashes)
        Pattern(
            name="aadhaar_dashed",
            regex=r"\b[2-9][0-9]{3}-[0-9]{4}-[0-9]{4}\b",
            score=0.85,
        ),
        # Format: XXXXXXXXXXXX (continuous)
        Pattern(
            name="aadhaar_continuous",
            regex=r"\b[2-9][0-9]{11}\b",
            score=0.7,  # Lower score because 12-digit numbers are common
        ),
    ]
    
    CONTEXT_WORDS = [
        "aadhaar", "aadhar", "uidai", "uid", "aadhaar number",
        "aadhaar no", "aadhaar card", "unique identification",
        "aadhaar#", "adhar"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_AADHAAR",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianPhoneRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Phone Numbers.
    
    Indian Mobile Format:
    - 10 digits starting with 6, 7, 8, or 9
    - Can have +91 or 0 prefix
    - Can have spaces or dashes
    """
    
    PATTERNS = [
        # +91 followed by 10 digits
        Pattern(
            name="indian_phone_intl",
            regex=r"\+91[-\s]?[6-9][0-9]{9}\b",
            score=0.9,
        ),
        # 0 followed by 10 digits (STD format)
        Pattern(
            name="indian_phone_std",
            regex=r"\b0[6-9][0-9]{9}\b",
            score=0.85,
        ),
        # Plain 10 digits starting with 6-9
        Pattern(
            name="indian_phone_plain",
            regex=r"\b[6-9][0-9]{9}\b",
            score=0.7,
        ),
        # With spaces: XXX XXX XXXX
        Pattern(
            name="indian_phone_spaced",
            regex=r"\b[6-9][0-9]{2}[-\s][0-9]{3}[-\s][0-9]{4}\b",
            score=0.8,
        ),
    ]
    
    CONTEXT_WORDS = [
        "phone", "mobile", "contact", "cell", "telephone",
        "whatsapp", "call", "sms", "number", "ph", "mob"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianVoterIDRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Voter ID (EPIC).
    
    Format: 3 letters followed by 7 digits
    Example: ABC1234567
    """
    
    PATTERNS = [
        Pattern(
            name="voter_id_pattern",
            regex=r"\b[A-Z]{3}[0-9]{7}\b",
            score=0.75,
        ),
    ]
    
    CONTEXT_WORDS = [
        "voter", "voter id", "epic", "election", "electoral",
        "voter card", "election card", "voter id card"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_VOTER_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianPassportRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Passport Number.
    
    Format: 1 letter followed by 7 digits
    - First letter indicates passport office
    - Can also be: 1 letter, 2 digits (year), 7 digits
    """
    
    PATTERNS = [
        # Standard format: A1234567
        Pattern(
            name="passport_standard",
            regex=r"\b[A-PR-WY-Z][0-9]{7}\b",
            score=0.75,
        ),
        # New format with issue year
        Pattern(
            name="passport_new",
            regex=r"\b[A-PR-WY-Z][0-9]{2}[0-9]{7}\b",
            score=0.8,
        ),
    ]
    
    CONTEXT_WORDS = [
        "passport", "passport number", "passport no", "travel document",
        "passport#", "indian passport"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_PASSPORT",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianDrivingLicenseRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Driving License.
    
    Format varies by state but generally:
    - 2 letters (state code) + 2 digits (RTO code) + Year + 7 digits
    - Example: MH01 2020 0001234
    """
    
    PATTERNS = [
        # Standard format with spaces
        Pattern(
            name="dl_spaced",
            regex=r"\b[A-Z]{2}[-\s]?[0-9]{2}[-\s]?(?:19|20)[0-9]{2}[-\s]?[0-9]{7}\b",
            score=0.85,
        ),
        # Compact format
        Pattern(
            name="dl_compact",
            regex=r"\b[A-Z]{2}[0-9]{2}(?:19|20)[0-9]{9}\b",
            score=0.8,
        ),
        # Older format
        Pattern(
            name="dl_old",
            regex=r"\b[A-Z]{2}[0-9]{13}\b",
            score=0.7,
        ),
    ]
    
    CONTEXT_WORDS = [
        "driving license", "driver license", "dl", "driving licence",
        "driver's license", "dl number", "dl no", "rto"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_DRIVING_LICENSE",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianGSTRecognizer(PatternRecognizer):
    """
    Recognizer for Indian GST Number (GSTIN).
    
    Format: 15 characters
    - 2 digits: State code
    - 10 characters: PAN
    - 1 digit: Entity number
    - 1 character: 'Z' by default
    - 1 character: Checksum
    """
    
    PATTERNS = [
        Pattern(
            name="gst_pattern",
            regex=r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9][Z][A-Z0-9]\b",
            score=0.9,
        ),
    ]
    
    CONTEXT_WORDS = [
        "gst", "gstin", "gst number", "gst no", "goods and services tax",
        "tax number", "gst#"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_GST",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianIFSCRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Bank IFSC Code.
    
    Format: 11 characters
    - First 4: Bank code (letters)
    - 5th: 0 (reserved)
    - Last 6: Branch code (alphanumeric)
    """
    
    PATTERNS = [
        Pattern(
            name="ifsc_pattern",
            regex=r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
            score=0.85,
        ),
    ]
    
    CONTEXT_WORDS = [
        "ifsc", "ifsc code", "bank code", "branch code",
        "neft", "rtgs", "imps", "bank transfer"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_IFSC",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


class IndianBankAccountRecognizer(PatternRecognizer):
    """
    Recognizer for Indian Bank Account Numbers.
    
    Format: 9-18 digits (varies by bank)
    - No standard format across banks
    - Uses context heavily for detection
    """
    
    PATTERNS = [
        # Most common: 11-16 digits
        Pattern(
            name="bank_account_common",
            regex=r"\b[0-9]{11,16}\b",
            score=0.4,  # Low base score, relies on context
        ),
        # SBI format: 11 digits
        Pattern(
            name="bank_account_sbi",
            regex=r"\b[0-9]{11}\b",
            score=0.35,
        ),
    ]
    
    CONTEXT_WORDS = [
        "account", "account number", "a/c", "bank account",
        "account no", "savings account", "current account",
        "account#", "acct"
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="IN_BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


def get_indian_recognizers() -> List[PatternRecognizer]:
    """
    Factory function to get all Indian PII recognizers.
    
    Returns:
        List of initialized recognizer instances.
    """
    return [
        IndianPANRecognizer(),
        IndianAadhaarRecognizer(),
        IndianPhoneRecognizer(),
        IndianVoterIDRecognizer(),
        IndianPassportRecognizer(),
        IndianDrivingLicenseRecognizer(),
        IndianGSTRecognizer(),
        IndianIFSCRecognizer(),
        IndianBankAccountRecognizer(),
    ]
