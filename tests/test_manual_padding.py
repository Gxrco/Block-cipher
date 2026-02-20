"""
Tests para las funciones de padding PKCS#7.
"""

import pytest
from src.manual_padding import pkcs7_pad, pkcs7_unpad


class TestPKCS7Pad:
    """Tests para la función pkcs7_pad."""

    def test_pad_basic_example(self):
        """Test con el ejemplo básico de la documentación."""
        result = pkcs7_pad(b"HOLA", 8)
        assert result.hex() == '484f4c4104040404'
        assert len(result) == 8
        assert result[-4:] == b'\x04\x04\x04\x04'

    def test_pad_exact_block_size(self):
        """Test cuando los datos son exactamente del tamaño del bloque."""
        result = pkcs7_pad(b"12345678", 8)
        assert result.hex() == '31323334353637380808080808080808'
        assert len(result) == 16
        assert result[-8:] == b'\x08\x08\x08\x08\x08\x08\x08\x08'

    def test_pad_empty_data(self):
        """Test con datos vacíos."""
        result = pkcs7_pad(b"", 8)
        assert len(result) == 8
        assert result == b'\x08\x08\x08\x08\x08\x08\x08\x08'

    def test_pad_one_byte_missing(self):
        """Test cuando falta un solo byte para completar el bloque."""
        result = pkcs7_pad(b"1234567", 8)
        assert len(result) == 8
        assert result[-1:] == b'\x01'
        assert result == b"1234567\x01"

    def test_pad_different_block_sizes(self):
        """Test con diferentes tamaños de bloque."""
        # Block size 16 (AES)
        result = pkcs7_pad(b"HOLA", 16)
        assert len(result) == 16
        assert result[-12:] == b'\x0c' * 12

        # Block size 4
        result = pkcs7_pad(b"ABC", 4)
        assert len(result) == 4
        assert result[-1:] == b'\x01'

    def test_pad_multiple_blocks_needed(self):
        """Test cuando se necesitan múltiples bloques."""
        data = b"A" * 10
        result = pkcs7_pad(data, 8)
        assert len(result) == 16
        assert result[-6:] == b'\x06' * 6

    def test_pad_preserves_original_data(self):
        """Test que el padding no modifica los datos originales."""
        data = b"HOLA MUNDO"
        result = pkcs7_pad(data, 8)
        assert result[:len(data)] == data

    def test_pad_with_binary_data(self):
        """Test con datos binarios arbitrarios."""
        data = bytes([0x00, 0xFF, 0xAA, 0x55])
        result = pkcs7_pad(data, 8)
        assert len(result) == 8
        assert result[:4] == data
        assert result[4:] == b'\x04\x04\x04\x04'


class TestPKCS7Unpad:
    """Tests para la función pkcs7_unpad."""

    def test_unpad_basic_example(self):
        """Test con el ejemplo básico de la documentación."""
        padded = pkcs7_pad(b"HOLA", 8)
        result = pkcs7_unpad(padded)
        assert result == b'HOLA'

    def test_unpad_exact_block_size(self):
        """Test cuando el dato original era exactamente del tamaño del bloque."""
        padded = pkcs7_pad(b"12345678", 8)
        result = pkcs7_unpad(padded)
        assert result == b"12345678"

    def test_unpad_empty_data(self):
        """Test con datos que originalmente estaban vacíos."""
        padded = pkcs7_pad(b"", 8)
        result = pkcs7_unpad(padded)
        assert result == b""

    def test_unpad_one_byte_padding(self):
        """Test con padding de un solo byte."""
        padded = b"1234567\x01"
        result = pkcs7_unpad(padded)
        assert result == b"1234567"

    def test_unpad_full_block_padding(self):
        """Test con un bloque completo de padding."""
        data = b"12345678" + b'\x08' * 8
        result = pkcs7_unpad(data)
        assert result == b"12345678"

    def test_unpad_different_padding_lengths(self):
        """Test con diferentes longitudes de padding."""
        for i in range(1, 9):
            data = b"A" * (8 - i)
            padded = pkcs7_pad(data, 8)
            result = pkcs7_unpad(padded)
            assert result == data

    def test_unpad_with_binary_data(self):
        """Test con datos binarios arbitrarios."""
        data = bytes([0x00, 0xFF, 0xAA, 0x55])
        padded = pkcs7_pad(data, 8)
        result = pkcs7_unpad(padded)
        assert result == data


class TestRoundTrip:
    """Tests para verificar que pad y unpad son operaciones inversas."""

    def test_roundtrip_various_lengths(self):
        """Test que pad seguido de unpad devuelve el dato original."""
        for length in range(0, 25):
            data = b"X" * length
            padded = pkcs7_pad(data, 8)
            unpadded = pkcs7_unpad(padded)
            assert unpadded == data, f"Failed for length {length}"

    def test_roundtrip_with_text(self):
        """Test con texto real."""
        messages = [
            b"Hola Mundo",
            b"Este es un mensaje de prueba",
            b"A",
            b"12345678",
            b"",
            b"PKCS#7 padding test"
        ]
        for msg in messages:
            padded = pkcs7_pad(msg, 8)
            unpadded = pkcs7_unpad(padded)
            assert unpadded == msg

    def test_roundtrip_different_block_sizes(self):
        """Test round-trip con diferentes tamaños de bloque."""
        data = b"Test message"
        for block_size in [4, 8, 16, 32]:
            padded = pkcs7_pad(data, block_size)
            unpadded = pkcs7_unpad(padded)
            assert unpadded == data
            assert len(padded) % block_size == 0


class TestPaddingProperties:
    """Tests para verificar propiedades del padding PKCS#7."""

    def test_padded_length_is_multiple_of_block_size(self):
        """Verifica que los datos con padding sean múltiplo del tamaño de bloque."""
        for length in range(0, 20):
            data = b"X" * length
            padded = pkcs7_pad(data, 8)
            assert len(padded) % 8 == 0

    def test_padding_bytes_all_same_value(self):
        """Verifica que todos los bytes de padding tengan el mismo valor."""
        data = b"HOLA"
        padded = pkcs7_pad(data, 8)
        padding_length = padded[-1]
        padding_bytes = padded[-padding_length:]
        assert all(b == padding_length for b in padding_bytes)

    def test_padding_value_equals_padding_length(self):
        """Verifica que el valor del padding sea igual a su longitud."""
        for i in range(1, 9):
            data = b"X" * (8 - i)
            padded = pkcs7_pad(data, 8)
            padding_length = padded[-1]
            assert padding_length == i

    def test_minimum_padding_is_one_byte(self):
        """Verifica que siempre haya al menos un byte de padding."""
        for length in range(0, 20):
            data = b"X" * length
            padded = pkcs7_pad(data, 8)
            assert len(padded) > len(data)
            assert len(padded) - len(data) >= 1
            assert len(padded) - len(data) <= 8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
