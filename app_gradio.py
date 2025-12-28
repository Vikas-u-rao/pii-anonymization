"""
Gradio Frontend for PII Anonymization Gateway.
A simple, interactive UI for demonstrating PII detection and anonymization.
"""

import gradio as gr
import uuid
import logging
from anonymizer_engine import PIIAnonymizer
from llm_client import OpenAIClient
from config import get_settings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
anonymizer = PIIAnonymizer(use_indian_recognizers=True)
settings = get_settings()

# Initialize LLM client (may be None if no API key)
try:
    llm_client = OpenAIClient()
    llm_available = llm_client.client is not None
    logger.info(f"LLM client initialized: {settings.llm_provider} - Available: {llm_available}")
except Exception as e:
    llm_client = None
    llm_available = False
    logger.warning(f"LLM client not available: {e}")

# Store mappings for de-anonymization (in-memory for demo)
session_mappings: dict[str, dict[str, str]] = {}


def anonymize_text(text: str) -> tuple[str, str, str]:
    """
    Anonymize PII in the input text.
    
    Args:
        text: Input text containing PII
        
    Returns:
        Tuple of (anonymized_text, entities_info, session_id)
    """
    if not text or not text.strip():
        return "", "No text provided", ""
    
    result = anonymizer.anonymize(text)
    
    # Generate a simple session ID
    session_id = str(uuid.uuid4())[:8]
    
    # Store mapping for de-anonymization
    session_mappings[session_id] = result.mapping
    
    # Format entities for display
    if result.entities_found:
        entities_info = "**Entities Detected:**\n\n"
        for entity in result.entities_found:
            # Handle both dict and object formats
            if isinstance(entity, dict):
                entity_type = entity.get("entity_type") or entity.get("type", "UNKNOWN")
                original = entity.get("original_text") or entity.get("original", "")
                placeholder = entity.get("placeholder", "")
                score = entity.get("confidence") or entity.get("score", 0.0)
            else:
                entity_type = entity.entity_type
                original = entity.original_text
                placeholder = entity.placeholder
                score = getattr(entity, "confidence", getattr(entity, "score", 0.0))
            
            entities_info += f"- **{entity_type}**: `{original}` → `{placeholder}` (confidence: {score:.2f})\n"
    else:
        entities_info = "No PII entities detected."
    
    return result.anonymized_text, entities_info, session_id


def deanonymize_text(text: str, session_id: str) -> str:
    """
    Restore original PII values in the text.
    
    Args:
        text: Anonymized text with placeholders
        session_id: Session ID from anonymization
        
    Returns:
        De-anonymized text with original values
    """
    if not text or not text.strip():
        return "No text provided"
    
    if not session_id or not session_id.strip():
        return "Please provide a Session ID from a previous anonymization"
    
    mapping = session_mappings.get(session_id.strip())
    if not mapping:
        return f"Session ID '{session_id}' not found. It may have expired or is invalid."
    
    return anonymizer.de_anonymize(text, mapping)


def chat_with_llm(user_message: str) -> tuple[str, str, str, str, str]:
    """
    Full PII protection flow: Anonymize → Send to LLM → De-anonymize response.
    
    Args:
        user_message: User's message containing PII
        
    Returns:
        Tuple of (original, anonymized, llm_response_raw, final_response, flow_explanation)
    """
    if not user_message or not user_message.strip():
        return "", "", "", "", "Please enter a message."
    
    if not llm_available:
        provider = settings.llm_provider
        return (
            user_message,
            "",
            "",
            "",
            f"**Error:** {provider.upper()} API key not configured.\n\n"
            f"Please set `{provider.upper()}_API_KEY` in your `.env` file to use this feature."
        )
    
    try:
        # Step 1: Anonymize the user message
        result = anonymizer.anonymize(user_message)
        anonymized_message = result.anonymized_text
        mapping = result.mapping
        
        # Build entities display
        entities_display = ""
        if result.entities_found:
            entities_display = "\n**PII Detected & Protected:**\n"
            for entity in result.entities_found:
                if isinstance(entity, dict):
                    entity_type = entity.get("type", "UNKNOWN")
                    original = entity.get("original", "")
                    placeholder = entity.get("placeholder", "")
                else:
                    entity_type = entity.entity_type
                    original = entity.original_text
                    placeholder = entity.placeholder
                entities_display += f"- `{original}` → `{placeholder}`\n"
        
        # Step 2: Send anonymized message to LLM
        messages = [
            {"role": "system", "content": """You are a helpful assistant. 

IMPORTANT RULES:
1. When you see placeholders like [PERSON_1], [EMAIL_ADDRESS_1], [IN_PHONE_NUMBER_1], etc., use them EXACTLY as-is in your response. These represent protected personal information.
2. Write COMPLETE responses - do NOT add your own placeholders like [YOUR_NAME], [COMPANY_NAME], [DATE], etc.
3. If you need information that wasn't provided, make a reasonable assumption or ask for it - don't use placeholder brackets.
4. Generate ready-to-use content, not templates.

Example: If user asks to write an email and their name shows as [PERSON_1], your response should use [PERSON_1] directly, not create new placeholders."""},
            {"role": "user", "content": anonymized_message}
        ]
        
        llm_response_raw = llm_client.chat_sync(messages)
        
        # Step 3: De-anonymize the LLM response
        final_response = anonymizer.de_anonymize(llm_response_raw, mapping)
        
        # Build flow explanation
        flow_explanation = f"""
### How Your Data Was Protected

**Step 1: PII Detection & Anonymization**
Your message was scanned for sensitive information.
{entities_display}

**Step 2: Safe LLM Query**
The anonymized message was sent to {settings.llm_provider.upper()}.
The LLM never saw your actual personal information!

**Step 3: Response Restoration**
Placeholders in the LLM's response were replaced with your original data.

---
*Mapping stored in memory. In production, this uses Redis with encryption.*
"""
        
        return (
            user_message,
            anonymized_message,
            llm_response_raw,
            final_response,
            flow_explanation
        )
        
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        return (
            user_message,
            "",
            "",
            "",
            f"**Error:** {str(e)}\n\nPlease check your API key and try again."
        )


def create_demo_examples() -> list[list[str]]:
    """Generate real-world example inputs for the demo."""
    return [
        # Customer Support - Summarize complaint
        ["Summarize this customer complaint: Hi, I'm Rahul Sharma (rahul.sharma@gmail.com, +91-9876543210). I ordered a laptop on Dec 1st but it arrived damaged. Order #12345. Please help!"],
        
        # HR - Draft email response
        ["Write a professional response to this job applicant: Dear HR, I'm Priya Patel applying for the Software Engineer role. My experience includes 3 years at TCS. Contact: priya.patel@outlook.com, Phone: 8765432109"],
        
        # Healthcare - Summarize patient notes
        ["Summarize these patient notes: Patient John Smith (DOB: 15/03/1985, SSN: 123-45-6789) presented with chest pain. Dr. Sarah Johnson prescribed medication. Follow-up scheduled for next week."],
        
        # Legal - Analyze contract clause
        ["Explain this contract clause in simple terms: The party of the first part, Amit Verma (amit.verma@company.com), agrees to pay Sunita Reddy the sum of Rs. 5,00,000 upon completion of services."],
        
        # Finance - Explain transaction
        ["Why was this transaction flagged? Transaction: Rs. 50,000 from account holder Vikram Singh (Account: 12345678901, IFSC: HDFC0001234) to unknown beneficiary on 12/08/2024 at 2:30 AM"],
        
        # Education - Grade feedback
        ["Help me write feedback for this student: Ananya Krishnan (Student ID: 2024CS001, ananya.k@university.edu) scored 78/100 on the midterm. She needs to improve in data structures."],
    ]


# Build the Gradio interface
with gr.Blocks(title="PII Anonymization Gateway") as demo:
    
    # Header
    gr.Markdown(
        """
        # 🛡️ PII Anonymization Gateway
        
        **Protect sensitive customer/employee data before sending prompts to ChatGPT, Claude, or other LLMs.**
        
        ### Real-World Use Cases
        - **Customer Support**: Summarize complaints without exposing customer details
        - **HR/Recruiting**: Draft responses to applicants while protecting personal info
        - **Healthcare**: Analyze patient notes without violating HIPAA
        - **Legal**: Review contracts without exposing party identities
        - **Finance**: Investigate transactions without leaking account details
        
        PII automatically detected: **Names, Emails, Phone Numbers, SSN, Credit Cards, and Indian IDs (PAN, Aadhaar, IFSC, etc.)**
        """
    )
    
    with gr.Tabs():
        # Tab 1: Chat with LLM (Primary feature)
        with gr.Tab("🤖 Chat with LLM"):
            gr.Markdown(
                """
                ### Try the Full PII Protection Flow
                Enter a message with personal information. Watch how it's anonymized before being sent to the LLM, 
                and then restored in the response. **The LLM never sees your actual data!**
                """
            )
            
            with gr.Row():
                with gr.Column(scale=1):
                    chat_input = gr.Textbox(
                        label="Your Message (with PII)",
                        placeholder="Example: Hi, I'm Rahul Sharma (rahul.sharma@gmail.com). Can you help me write a professional bio?",
                        lines=4,
                    )
                    chat_btn = gr.Button("Send to LLM (Protected)", variant="primary", size="lg")
                    
                    gr.Examples(
                        examples=[
                            ["Hi, I'm Rahul Sharma (rahul.sharma@gmail.com, +91-9876543210). Can you help me write a professional bio for LinkedIn?"],
                            ["Summarize this complaint: Customer John Smith (SSN: 123-45-6789) ordered laptop #12345 but it arrived damaged."],
                            ["Write feedback for student Ananya Krishnan (ananya.k@university.edu) who scored 78/100 on data structures."],
                            ["Explain why this transaction was flagged: Rs. 50,000 from Vikram Singh (IFSC: HDFC0001234) at 2:30 AM."],
                        ],
                        inputs=chat_input,
                        label="Try these examples:",
                    )
            
            with gr.Row():
                with gr.Column():
                    gr.Markdown("#### Step 1: Your Original Message")
                    original_display = gr.Textbox(label="", lines=3, interactive=False)
                    
                    gr.Markdown("#### Step 2: What the LLM Sees (Anonymized)")
                    anonymized_display = gr.Textbox(label="", lines=3, interactive=False)
                
                with gr.Column():
                    gr.Markdown("#### Step 3: LLM's Raw Response (with placeholders)")
                    llm_raw_display = gr.Textbox(label="", lines=3, interactive=False)
                    
                    gr.Markdown("#### Step 4: Final Response (De-anonymized)")
                    final_display = gr.Textbox(label="", lines=3, interactive=False)
            
            with gr.Row():
                flow_explanation = gr.Markdown(label="Protection Summary")
            
            chat_btn.click(
                fn=chat_with_llm,
                inputs=[chat_input],
                outputs=[original_display, anonymized_display, llm_raw_display, final_display, flow_explanation],
            )
        
        # Tab 2: Anonymize (Manual)
        with gr.Tab("🔒 Anonymize Only"):
            with gr.Row():
                with gr.Column():
                    input_text = gr.Textbox(
                        label="Input Text",
                        placeholder="Enter text containing PII (names, emails, phone numbers, PAN, Aadhaar, etc.)",
                        lines=5,
                    )
                    anonymize_btn = gr.Button("Anonymize", variant="primary")
                    
                    gr.Examples(
                        examples=create_demo_examples(),
                        inputs=input_text,
                        label="Try these examples:",
                    )
                
                with gr.Column():
                    output_text = gr.Textbox(
                        label="Anonymized Text",
                        lines=5,
                        interactive=False,
                    )
                    session_id_output = gr.Textbox(
                        label="Session ID (save this for de-anonymization)",
                        interactive=False,
                    )
                    entities_output = gr.Markdown(label="Detected Entities")
            
            anonymize_btn.click(
                fn=anonymize_text,
                inputs=[input_text],
                outputs=[output_text, entities_output, session_id_output],
            )
        
        # Tab 3: De-anonymize
        with gr.Tab("🔓 De-anonymize"):
            with gr.Row():
                with gr.Column():
                    anon_input = gr.Textbox(
                        label="Anonymized Text",
                        placeholder="Paste anonymized text with placeholders like [PERSON_1], [IN_PAN_1]",
                        lines=5,
                    )
                    session_id_input = gr.Textbox(
                        label="Session ID",
                        placeholder="Enter the Session ID from anonymization",
                    )
                    deanonymize_btn = gr.Button("De-anonymize", variant="primary")
                
                with gr.Column():
                    restored_text = gr.Textbox(
                        label="Restored Text",
                        lines=5,
                        interactive=False,
                    )
            
            deanonymize_btn.click(
                fn=deanonymize_text,
                inputs=[anon_input, session_id_input],
                outputs=[restored_text],
            )
        
        # Tab 4: About
        with gr.Tab("ℹ️ About"):
            gr.Markdown(
                """
                ## How It Works
                
                ```
                User Input → PII Detection → Anonymization → Safe for LLM
                                    ↓
                              Mapping Stored
                                    ↓
                LLM Response → De-anonymization → Original PII Restored
                ```
                
                ## Supported PII Types
                
                | Category | Types |
                |----------|-------|
                | **Standard** | PERSON, EMAIL, PHONE, CREDIT_CARD, SSN, DATE, LOCATION, IP_ADDRESS |
                | **Indian** | IN_PAN, IN_AADHAAR, IN_PHONE, IN_IFSC, IN_GST, IN_VOTER_ID, IN_PASSPORT, IN_DRIVING_LICENSE |
                
                ## Technology Stack
                
                - **Backend**: FastAPI + Python
                - **PII Detection**: Microsoft Presidio
                - **NLP Model**: spaCy (en_core_web_lg)
                - **Frontend**: Gradio
                
                ## API Endpoints
                
                - `POST /anonymize` - Anonymize text
                - `POST /deanonymize` - Restore original values
                - `POST /chat` - Chat with LLM (auto PII protection)
                - `GET /health` - Health check
                
                ---
                
                **GitHub**: [View Source Code](https://github.com/Vikas-u-rao/pii-anonymization)
                """
            )
    
    # Footer
    gr.Markdown(
        """
        ---
        <p style="text-align: center; color: #666;">
        Built with ❤️ using FastAPI, Presidio, and Gradio
        </p>
        """
    )


if __name__ == "__main__":
    # For Hugging Face Spaces, don't specify server_name or server_port
    # For local development, you can uncomment these
    import os
    
    if os.getenv("SPACE_ID"):  # Running on Hugging Face Spaces
        demo.launch()
    else:  # Running locally
        demo.launch(
            server_name="127.0.0.1",
            server_port=7862,
            share=False,  # Set to True for temporary public URL
        )
