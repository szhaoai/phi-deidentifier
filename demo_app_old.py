"""
Streamlit Demo App for PHI/PII De-identifier

A simple two-column layout:
- Left: input textarea + config options
- Right: highlighted preview + de-identified output
"""

import streamlit as st
import json

# MUST be called first, before any other Streamlit commands
st.set_page_config(page_title="PHI/PII De-identifier", layout="wide")

# Now import and debug NER
from phi_pii_deidentifier import deidentify, ENTITY_COLORS

# Debug: Check if NER is available (after set_page_config)
if 'debug_shown' not in st.session_state:
    from phi_pii_deidentifier import PIIHybridDetector
    detector = PIIHybridDetector()
    st.sidebar.info(f"NER Available: {detector.ner_available}")
    if detector.nlp:
        st.sidebar.info(f"spaCy model: {detector.nlp.meta.get('name', 'unknown')}")
    st.session_state['debug_shown'] = True


def render_highlighted_text(text: str, highlights: list) -> str:
    """Build HTML with highlighted spans for the original text."""
    if not highlights:
        return text
    
    sorted_hl = sorted(highlights, key=lambda x: x["start"])
    html_parts = []
    last_end = 0
    
    for hl in sorted_hl:
        start, end = hl["start"], hl["end"]
        if start >= last_end:
            html_parts.append(text[last_end:start])
            color = hl.get("color", "#FFE082")
            tooltip = hl.get("tooltip", hl.get("entity_type", ""))
            html_parts.append(
                f'<span style="background-color: {color}; padding: 2px 4px; border-radius: 3px;" '
                f'title="{tooltip}">{text[start:end]}</span>'
            )
            last_end = end
    
    html_parts.append(text[last_end:])
    return "".join(html_parts)


def main():
    st.title("PHI/PII De-identifier")
    st.markdown("Production-grade de-identification pipeline for sensitive data (PII/PHI)")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Input Text")
        
        with st.expander("Configuration", expanded=False):
            mode = st.selectbox("Mode", ["SAFE_HARBOR", "RISK_BASED"], index=0)
            policy = st.selectbox("Policy", ["HIPAA", "GENERIC_PII", "CUSTOM"], index=0)
            default_action = st.selectbox("Default Action", ["REDACT", "MASK", "HASH", "TOKENIZE"], index=0)
        
        input_text = st.text_area(
            "Paste text to de-identify:",
            height=300,
            placeholder="Example: Patient John Smith (SSN: 123-45-6789) visited on 01/15/2024..."
        )
        
        if st.button("De-identify", type="primary"):
            if input_text.strip():
                with st.spinner("Detecting and redacting PII/PHI..."):
                    result = deidentify(
                        input_text,
                        mode=mode,
                        policy=policy,
                        default_action=default_action
                    )
                    st.session_state["result"] = result
            else:
                st.warning("Please enter some text to de-identify.")
    
    with col2:
        st.subheader("Preview & Output")
        
        if "result" in st.session_state:
            result = st.session_state["result"]
            result_data = result.get("result", {})
            
            st.markdown("**Highlighted Preview**")
            highlights = result_data.get("highlights", [])
            highlighted_html = render_highlighted_text(input_text, highlights)
            st.markdown(
                f'<div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; '
                f'line-height: 1.8; font-family: monospace; white-space: pre-wrap;">'
                f'{highlighted_html}</div>',
                unsafe_allow_html=True
            )
            
            st.markdown("**De-identified Text**")
            deid_text = result_data.get("deidentified_text", "")
            st.text_area(
                "Clean output:",
                value=deid_text,
                height=150,
                key="deid_output"
            )
            
            c1, c2 = st.columns(2)
            with c1:
                st.code(deid_text, language=None)
            with c2:
                if st.button("Copy De-identified"):
                    st.toast("Copied to clipboard!", icon="✅")
            
            st.markdown("---")
            summary = result_data.get("summary", {})
            c1, c2, c3 = st.columns(3)
            c1.metric("Entities Found", summary.get("entities_found", 0))
            c2.metric("Entities Transformed", summary.get("entities_transformed", 0))
            c3.metric("Review Required", "Yes" if summary.get("review_required") else "No")
            
            st.markdown("**Entity Legend**")
            legend_cols = st.columns(3)
            for i, (entity_type, color) in enumerate(ENTITY_COLORS.items()):
                with legend_cols[i % 3]:
                    st.markdown(
                        f'<span style="background-color: {color}; padding: 2px 6px; '
                        f'border-radius: 3px; font-size: 12px;">{entity_type}</span>',
                        unsafe_allow_html=True
                    )
            
            st.markdown("---")
            st.markdown("**Identified Elements**")
            entities = result_data.get("entities", [])
            if entities:
                for entity in entities:
                    entity_type = entity.get("type", "")
                    confidence = entity.get("confidence", 0)
                    severity = entity.get("severity", "")
                    action = entity.get("action", "")
                    # Get the original value from the text
                    start = entity.get("start", 0)
                    end = entity.get("end", 0)
                    original_value = input_text[start:end] if start < len(input_text) and end <= len(input_text) else ""
                    
                    st.markdown(
                        f"**{entity_type}** | `{original_value}` | conf={confidence:.2f} | {severity} | {action}"
                    )
            else:
                st.info("No entities detected.")
            
            with st.expander("Full JSON Output"):
                st.json(result)
        else:
            st.info("Enter text and click De-identify to see results here.")
            
            if st.button("Use Sample Text"):
                sample = "Patient John Smith (SSN: 123-45-6789) visited on 01/15/2024. " \
                        "Contact: john.smith@email.com, Phone: 555-123-4567. " \
                        "Address: 123 Main Street, Boston, MA 02101."
                st.session_state["sample_text"] = sample
    
    st.markdown("---")
    st.caption("PHI/PII De-identifier | Default behavior is REDACTION for all detected entities | " \
              "Tooltips never reveal raw values")


if __name__ == "__main__":
    main()

