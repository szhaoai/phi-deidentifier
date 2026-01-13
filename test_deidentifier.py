"""
Test suite for PHI/PII De-identifier
"""

import pytest
import json
from phi_pii_deidentifier import deidentify, Deidentifier, DeidentifyRequest, EntityType


class TestDeidentifier:
    """Test cases for the de-identifier module."""
    
    def test_ssn_detection(self):
        """Test Social Security Number detection and redaction."""
        text = "Patient SSN: 123-45-6789"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "123-45-6789" not in deid_text
        
        assert "[REDACTED]" in deid_text
        assert result["result"]["summary"]["entities_found"] >= 1
    
    def test_email_detection(self):
        """Test email address detection and redaction."""
        text = "Contact: john.doe@example.com"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "john.doe@example.com" not in deid_text
        assert "[REDACTED]" in deid_text
    
    def test_phone_detection(self):
        """Test phone number detection and redaction."""
        text = "Phone: 555-123-4567"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "555-123-4567" not in deid_text
        assert "[REDACTED]" in deid_text
    
    def test_date_detection(self):
        """Test date detection and redaction."""
        text = "Appointment on 01/15/2024"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "01/15/2024" not in deid_text
        assert "[REDACTED]" in deid_text
    
    def test_mrn_detection(self):
        """Test Medical Record Number detection."""
        text = "MRN: ABC123456"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "ABC123456" not in deid_text
        assert "[REDACTED]" in deid_text
    
    def test_ip_address_detection(self):
        """Test IP address detection and redaction."""
        text = "Source IP: 192.168.1.100"
        result = deidentify(text)
        deid_text = result["result"]["deidentified_text"]
        
        assert "192.168.1.100" not in deid_text
        assert "[REDACTED]" in deid_text
    
    def test_multiple_entities(self):
        """Test detection of multiple entity types."""
        text = "Patient John Smith (SSN: 123-45-6789) visited on 01/15/2024. Contact: john.smith@email.com"
        result = deidentify(text)
        
        assert result["result"]["summary"]["entities_found"] >= 4
        assert "[REDACTED]" in result["result"]["deidentified_text"]
    
    def test_highlights_format(self):
        """Test that highlights have correct format."""
        text = "SSN: 123-45-6789"
        result = deidentify(text)
        
        highlights = result["result"]["highlights"]
        assert len(highlights) >= 1
        
        highlight = highlights[0]
        assert "entity_id" in highlight
        assert "entity_type" in highlight
        assert "start" in highlight
        assert "end" in highlight
        assert "confidence" in highlight
        assert "severity" in highlight
        assert "action" in highlight
        assert "color" in highlight
    
    def test_no_pii_text(self):
        """Test text with no PII returns unchanged."""
        text = "The patient was discharged in good condition."
        result = deidentify(text)
        
        assert result["result"]["deidentified_text"] == text
        assert result["result"]["summary"]["entities_found"] == 0
    
    def test_request_format(self):
        """Test that request includes required fields."""
        text = "Test SSN: 123-45-6789"
        result = deidentify(text)
        
        request = result["request"]
        assert "mode" in request
        assert "policy" in request
        assert "default_action" in request
        assert "reversible" in request
        assert "locale" in request
        assert "timestamp_iso" in request
    
    def test_result_format(self):
        """Test that result has required fields."""
        text = "Test"
        result = deidentify(text)
        
        result_data = result["result"]
        assert "original_text_length" in result_data
        assert "deidentified_text" in result_data
        assert "summary" in result_data
        assert "highlights" in result_data
        assert "entities" in result_data
        assert "risks" in result_data
        assert "errors" in result_data
    
    def test_review_required_flag(self):
        """Test review_required flag is set correctly."""
        # With default REDACT action, all HIGH severity should be transformed
        text = "SSN: 123-45-6789"
        result = deidentify(text)
        
        assert result["result"]["summary"]["review_required"] == False
    
    def test_json_output(self):
        """Test that output is valid JSON."""
        text = "Test SSN: 123-45-6789"
        result = deidentify(text)
        
        # Should not raise exception
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        
        assert parsed["request"]["mode"] == "SAFE_HARBOR"
        assert parsed["result"]["deidentified_text"] != text


class TestConfigOptions:
    """Test configuration options."""
    
    def test_custom_mode(self):
        """Test with custom mode."""
        text = "Test SSN: 123-45-6789"
        result = deidentify(text, mode="RISK_BASED")
        
        assert result["request"]["mode"] == "RISK_BASED"
    
    def test_custom_policy(self):
        """Test with custom policy."""
        text = "Test SSN: 123-45-6789"
        result = deidentify(text, policy="GENERIC_PII")
        
        assert result["request"]["policy"] == "GENERIC_PII"
    
    def test_mask_action(self):
        """Test MASK action (currently defaults to REDACT in implementation)."""
        text = "Email: test@example.com"
        result = deidentify(text, default_action="MASK")
        deid_text = result["result"]["deidentified_text"]
        
        # Currently defaults to REDACT
        assert "[REDACTED]" in deid_text
    
    def test_tokenize_action(self):
        """Test TOKENIZE action (currently defaults to REDACT in implementation)."""
        text = "Email: test@example.com"
        result = deidentify(text, default_action="TOKENIZE")
        deid_text = result["result"]["deidentified_text"]
        
        # Currently defaults to REDACT
        assert "[REDACTED]" in deid_text


class TestEdgeCases:
    """Test edge cases."""
    
    def test_empty_text(self):
        """Test with empty text."""
        result = deidentify("")
        
        assert result["result"]["original_text_length"] == 0
        assert result["result"]["deidentified_text"] == ""
    
    def test_whitespace_only(self):
        """Test with whitespace only."""
        result = deidentify("   ")
        
        assert result["result"]["summary"]["entities_found"] == 0
    
    def test_overlapping_entities(self):
        """Test handling of overlapping entity spans."""
        # This tests the SpanOverlapResolver
        text = "John Smith"  # Could be detected as both PERSON and NAME in some patterns
        result = deidentify(text)
        
        # Should handle gracefully without errors
        assert result is not None
    
    def test_special_characters(self):
        """Test text with special characters."""
        text = "SSN: 123-45-6789! @#$%"
        result = deidentify(text)
        
        assert result["result"]["deidentified_text"] != text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
