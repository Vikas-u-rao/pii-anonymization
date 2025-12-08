from presidio_analyzer import AnalyzerEngine
import re

# Initialize the engine
analyzer = AnalyzerEngine()

def anonymize_and_map(text):
    results = analyzer.analyze(text=text, language='en')
    
    # --- FIX START: Handle Overlaps ---
    # 1. Sort by confidence score first (highest first)
    results.sort(key=lambda x: x.score, reverse=True)
    
    unique_results = []
    # Keep track of indices we have already processed
    # Format: set of (start, end) tuples
    occupied_indices = []

    for result in results:
        is_overlapping = False
        for start, end in occupied_indices:
            # Check if the current result overlaps with any existing one
            if max(start, result.start) < min(end, result.end):
                is_overlapping = True
                break
        
        if not is_overlapping:
            unique_results.append(result)
            occupied_indices.append((result.start, result.end))
    # --- FIX END ---

    # Now we sort by start index (reverse) like before for safe replacement
    unique_results.sort(key=lambda x: x.start, reverse=True)
    
    mapping = {}
    anonymized_text = text
    entity_counters = {}

    for result in unique_results:
        original_word = text[result.start:result.end]
        entity_type = result.entity_type
        
        if entity_type not in entity_counters:
            entity_counters[entity_type] = 1
        else:
            entity_counters[entity_type] += 1
            
        placeholder = f"[{entity_type}_{entity_counters[entity_type]}]"
        
        mapping[placeholder] = original_word
        
        anonymized_text = (
            anonymized_text[:result.start] + 
            placeholder + 
            anonymized_text[result.end:]
        )

    return anonymized_text, mapping

def de_anonymize(text, mapping):
    """
    Takes the LLM response and swaps [PERSON_1] back to 'Rohan'.
    """
    for placeholder, original_value in mapping.items():
        text = text.replace(placeholder, original_value)
    return text

# --- Simulation ---

original_prompt = "Hello, I am Rohan. My phone number is 9876543210."
print(f"1. ORIGINAL:  {original_prompt}")

# Step 1: Anonymize
clean_prompt, secret_map = anonymize_and_map(original_prompt)
print(f"2. SENDING TO LLM: {clean_prompt}")
print(f"   (Secret Map: {secret_map})")

# Step 2: Simulate LLM Response (The LLM sees [PERSON_1])
# Imagine ChatGPT replies this:
llm_reply = "Hello [PERSON_1], I have noted your number [PHONE_NUMBER_1]."
print(f"3. LLM RAW REPLY: {llm_reply}")

# Step 3: De-anonymize
final_output = de_anonymize(llm_reply, secret_map)
print(f"4. FINAL RESULT: {final_output}")