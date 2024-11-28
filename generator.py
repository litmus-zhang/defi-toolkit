import random
import requests
import hashlib
import secrets
from typing import List, Tuple


class SeedPhraseGenerator:
    def __init__(self):
        # Download word list from BIP39 English wordlist
        self.word_list = self._get_bip39_wordlist()
        self.valid_lengths = [12, 24]  # Valid lengths for seed phrases
        # Mapping of seed phrase lengths to required entropy bits
        self.entropy_bits = {
            12: 128,  # 128 bits of entropy for 12 words
            24: 256,  # 256 bits of entropy for 24 words
        }

    def _get_bip39_wordlist(self) -> List[str]:
        """Fetch the official BIP39 English wordlist."""
        try:
            url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
            response = requests.get(url)
            if response.status_code == 200:
                return response.text.strip().split("\n")
        except:
            print(
                "Warning: Unable to fetch BIP39 wordlist. Using fallback word generation."
            )
            return self._generate_fallback_wordlist()

    def _generate_fallback_wordlist(self) -> List[str]:
        """Generate a fallback wordlist using basic English words."""
        common_words = []
        with open("/usr/share/dict/words", "r") as f:
            for word in f:
                word = word.strip().lower()
                if 3 <= len(word) <= 8 and word.isalpha():
                    common_words.append(word)
        return common_words[:2048]  # BIP39 uses 2048 words

    def _generate_entropy(self, num_bits: int) -> bytes:
        """
        Generate cryptographically secure random entropy.

        Args:
            num_bits (int): Number of bits of entropy to generate

        Returns:
            bytes: Generated entropy
        """
        return secrets.token_bytes(num_bits // 8)

    def _bits_to_index(self, bits: str) -> int:
        """Convert 11 bits to an integer index."""
        return int(bits, 2)

    def _entropy_to_words(self, entropy: bytes) -> List[str]:
        """
        Convert entropy to mnemonic words according to BIP39 specification.

        Args:
            entropy (bytes): Random entropy bytes

        Returns:
            List[str]: List of mnemonic words
        """
        # Convert entropy to binary string
        binary = bin(int.from_bytes(entropy, byteorder="big"))[2:].zfill(
            len(entropy) * 8
        )

        # Calculate checksum
        checksum_length = len(entropy) * 8 // 32
        entropy_hash = hashlib.sha256(entropy).digest()
        checksum = bin(entropy_hash[0])[2:].zfill(8)[:checksum_length]

        # Combine entropy and checksum
        combined_bits = binary + checksum

        # Split into groups of 11 bits and convert to words
        words = []
        for i in range(0, len(combined_bits), 11):
            index = self._bits_to_index(combined_bits[i : i + 11])
            words.append(self.word_list[index])

        return words

    def generate_phrase(self, length: int = 12) -> Tuple[List[str], bool]:
        """
        Generate a cryptographically secure seed phrase of specified length.

        Args:
            length (int): Number of words in the seed phrase (12 or 24)

        Returns:
            Tuple[List[str], bool]: Generated phrase and validity status
        """
        if length not in self.valid_lengths:
            raise ValueError(f"Length must be one of {self.valid_lengths}")

        # Generate entropy
        entropy = self._generate_entropy(self.entropy_bits[length])

        # Convert entropy to words
        phrase = self._entropy_to_words(entropy)

        # Validate the generated phrase
        is_valid = self.validate_phrase(phrase)

        return phrase, is_valid

    def validate_phrase(self, phrase: List[str]) -> bool:
        """
        Validate if a phrase is a legitimate seed phrase.

        Args:
            phrase (List[str]): List of words to validate

        Returns:
            bool: True if phrase is valid, False otherwise
        """
        # Check length
        if len(phrase) not in self.valid_lengths:
            return False

        # Check if all words are in the BIP39 wordlist
        if not all(word.lower() in self.word_list for word in phrase):
            return False

        # Convert words back to indices
        try:
            indices = [self.word_list.index(word.lower()) for word in phrase]

            # Convert indices to binary
            bits = "".join(bin(index)[2:].zfill(11) for index in indices)

            # Split entropy and checksum
            ent_length = len(phrase) * 11 * 32 // 33
            entropy_bits = bits[:ent_length]
            checksum_bits = bits[ent_length:]

            # Convert entropy bits to bytes
            entropy = int(entropy_bits, 2).to_bytes(
                (ent_length + 7) // 8, byteorder="big"
            )

            # Calculate checksum
            checksum_length = len(phrase) * 11 - ent_length
            entropy_hash = hashlib.sha256(entropy).digest()
            calculated_checksum = bin(entropy_hash[0])[2:].zfill(8)[:checksum_length]

            # Verify checksum
            return checksum_bits == calculated_checksum
        except:
            return False


def main():
    generator = SeedPhraseGenerator()

    # Generate and validate phrases of different lengths
    for length in [12, 24]:
        print(f"\nGenerating {length}-word seed phrase with proper entropy:")
        phrase, is_valid = generator.generate_phrase(length)
        print("Generated phrase:", " ".join(phrase))
        print("Is valid:", is_valid)


if __name__ == "__main__":
    main()
