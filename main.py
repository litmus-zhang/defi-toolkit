import streamlit as st
from mnemonic import Mnemonic
from bip44 import Wallet
import requests

from coincurve import PrivateKey
from bip44 import Wallet
from bip44.utils import get_eth_addr

# mnemonic = "purity tunnel grid error scout long fruit false embody caught skin gate"
# w = Wallet(mnemonic)
# sk, pk = w.derive_account("eth", account=0)
# sk = PrivateKey(sk)
# sk.public_key.format() == pk
# True
# get_eth_addr(pk)
# "0x7aD23D6eD9a1D98E240988BED0d78e8C81Ec296C"


def generate_seed_phrase():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=256)


def get_wallet_address(seed_phrase):
    wallet = Wallet(seed_phrase)
    sk, pk = wallet.derive_account("eth", account=0)
    sk = PrivateKey(sk)
    if sk.public_key.format() == pk:
        return get_eth_addr(pk)
    return None


def check_balance(address) -> float:
    api_key = st.secrets["etherscan_api_key"]
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    response = requests.get(url)
    data = response.json()
    return float(int(data["result"]) / 10**18)  # Convert Wei to Ether


def main():
    st.title("Seed Phrase Generator")
    st.write(
        "This is a simple seed phrase generator that generates a BIP39 compliant seed phrase. The seed phrase is generated using entropy from the operating system's random number generator. The seed phrase is then validated to ensure it is a legitimate seed phrase."
    )

    st.write("Click the button below to generate a seed phrase.")

    if st.button("Generate Seed Phrase"):
        for _ in range(
            1_00_000
        ):  # Adjust the range for the number of wallets you want to generate
            seed_phrase = generate_seed_phrase()
            address = get_wallet_address(seed_phrase)
            balance = check_balance(address)
            st.write(f"{_+1}. address: {address}, balance:{balance}")
            if balance > 0:
                st.write(f"Wallet Address: {address}")
                st.write(f"Seed Phrase: {seed_phrase}")
                st.write(f"Balance: {balance} ETH")
                break  # Remove this if you want to find multiple wallets with balance


if __name__ == "__main__":
    main()
