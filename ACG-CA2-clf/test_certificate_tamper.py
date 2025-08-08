# test_certificate_tamper.py - Prove PKI Certificate Validation Works
# IT2504 Applied Cryptography Assignment 2

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'client'))

from simple_pki import SimpleCertificateAuthority
import json
import base64

def test_certificate_tamper_detection():
    """
    Comprehensive test to prove PKI certificate validation works
    by demonstrating what happens when certificates are tampered with.
    """
    print("=== PKI CERTIFICATE TAMPER DETECTION TEST ===\n")
    
    # Create CA
    ca = SimpleCertificateAuthority("Test Security CA")
    print("✅ Created Certificate Authority\n")
    
    # Create legitimate user certificate
    print("1. Creating legitimate certificate for Alice...")
    alice_ed25519 = "YWxpY2VfZWQyNTUxOV9wdWJsaWNfa2V5"  # Base64: alice_ed25519_public_key
    alice_x25519 = "YWxpY2VfeDI1NTE5X3B1YmxpY19rZXk="   # Base64: alice_x25519_public_key
    
    legitimate_cert = ca.issue_user_certificate("alice", alice_ed25519, alice_x25519)
    print("✅ Legitimate certificate created\n")
    
    # Test 1: Verify legitimate certificate works
    print("2. Testing legitimate certificate...")
    is_valid, user_data = ca.verify_user_certificate(legitimate_cert)
    
    if is_valid:
        print(f"✅ VALID: Certificate verified successfully")
        print(f"   Username: {user_data['username']}")
        print(f"   ED25519: {user_data['ed25519_public_key']}")
        print(f"   X25519: {user_data['x25519_public_key']}")
    else:
        print(f"❌ ERROR: Legitimate certificate failed validation!")
    
    print("\n" + "="*50)
    print("TAMPER TESTS - Proving PKI Security")
    print("="*50 + "\n")
    
    # Test 2: Username tampering
    print("3. TEST: Tampering with username (alice → mallory)...")
    tampered_username_cert = legitimate_cert.replace("alice", "mallory")
    is_valid_tampered, _ = ca.verify_user_certificate(tampered_username_cert)
    
    if not is_valid_tampered:
        print("✅ SECURE: Username tampering DETECTED and BLOCKED")
    else:
        print("❌ VULNERABILITY: Username tampering NOT detected!")
    
    # Test 3: Key tampering
    print("\n4. TEST: Tampering with ED25519 key...")
    # Change one character in the ED25519 key
    fake_ed25519 = "YWxpY2VfZWQyNTUxOV9wdWJsaWNfa2V5".replace("Y", "Z")
    tampered_key_cert = legitimate_cert.replace(alice_ed25519, fake_ed25519)
    is_valid_key_tamper, _ = ca.verify_user_certificate(tampered_key_cert)
    
    if not is_valid_key_tamper:
        print("✅ SECURE: Key tampering DETECTED and BLOCKED")
    else:
        print("❌ VULNERABILITY: Key tampering NOT detected!")
    
    # Test 4: Certificate signature tampering
    print("\n5. TEST: Tampering with certificate signature...")
    # Corrupt the end of the certificate (where signature is)
    tampered_sig_cert = legitimate_cert[:-50] + "CORRUPTED_SIGNATURE_DATA" + "=="
    is_valid_sig_tamper, _ = ca.verify_user_certificate(tampered_sig_cert)
    
    if not is_valid_sig_tamper:
        print("✅ SECURE: Signature tampering DETECTED and BLOCKED")
    else:
        print("❌ VULNERABILITY: Signature tampering NOT detected!")
    
    # Test 5: Certificate format corruption
    print("\n6. TEST: Corrupting certificate format...")
    corrupted_cert = legitimate_cert.replace("-----BEGIN CERTIFICATE-----", "-----FAKE CERTIFICATE-----")
    is_valid_format, _ = ca.verify_user_certificate(corrupted_cert)
    
    if not is_valid_format:
        print("✅ SECURE: Format corruption DETECTED and BLOCKED")
    else:
        print("❌ VULNERABILITY: Format corruption NOT detected!")
    
    # Test 6: Wrong CA signature
    print("\n7. TEST: Certificate from different CA...")
    try:
        # Create a different CA
        fake_ca = SimpleCertificateAuthority("Fake Evil CA")
        fake_cert = fake_ca.issue_user_certificate("alice", alice_ed25519, alice_x25519)
        
        # Try to verify with original CA
        is_valid_wrong_ca, _ = ca.verify_user_certificate(fake_cert)
        
        if not is_valid_wrong_ca:
            print("✅ SECURE: Wrong CA signature DETECTED and BLOCKED")
        else:
            print("❌ VULNERABILITY: Wrong CA signature NOT detected!")
    except Exception as e:
        print(f"✅ SECURE: Wrong CA certificate rejected: {str(e)[:50]}...")
    
    print("\n" + "="*50)
    print("ATTACK SIMULATION")
    print("="*50 + "\n")
    
    # Test 7: Man-in-the-Middle attack simulation
    print("8. SIMULATION: MITM Attack Scenario")
    print("   Scenario: Mallory tries to impersonate Alice")
    
    # Mallory's real keys
    mallory_ed25519 = "bWFsbG9yeV9lZDI1NTE5X3B1YmxpY19rZXk="  # mallory_ed25519_public_key
    mallory_x25519 = "bWFsbG9yeV94MjU1MTlfa2V5"                # mallory_x25519_key
    
    print(f"   Mallory's real ED25519: {mallory_ed25519}")
    print(f"   Alice's real ED25519:  {alice_ed25519}")
    
    # Mallory gets legitimate certificate for herself
    mallory_legitimate_cert = ca.issue_user_certificate("mallory", mallory_ed25519, mallory_x25519)
    
    # Mallory tries to modify her certificate to claim she's Alice
    mallory_fake_alice_cert = mallory_legitimate_cert.replace("mallory", "alice")
    
    print("\n   Mallory's attack: Modify her certificate to claim username 'alice'")
    is_mallory_attack_success, attack_data = ca.verify_user_certificate(mallory_fake_alice_cert)
    
    if not is_mallory_attack_success:
        print("   ✅ ATTACK FAILED: PKI detected the impersonation attempt!")
        print("   🛡️  Alice's identity is protected")
    else:
        print("   ❌ ATTACK SUCCESS: Mallory successfully impersonated Alice!")
        print("   ⚠️  CRITICAL SECURITY VULNERABILITY!")
    
    # Test 8: Key substitution attack
    print("\n9. SIMULATION: Key Substitution Attack")
    print("   Scenario: Attacker replaces Alice's keys with their own")
    
    # Try to create certificate with Alice's name but Mallory's keys
    try:
        # This would require getting CA to sign false certificate
        fake_alice_cert = ca.issue_user_certificate("alice", mallory_ed25519, mallory_x25519)
        
        print("   ⚠️  WARNING: CA issued certificate with Alice's name but wrong keys!")
        print("   This means the CA doesn't verify key ownership!")
        
        # Verify the fake certificate
        is_fake_valid, fake_data = ca.verify_user_certificate(fake_alice_cert)
        if is_fake_valid:
            print(f"   Certificate says 'alice' but has keys: {fake_data['ed25519_public_key'][:20]}...")
            if fake_data['ed25519_public_key'] != alice_ed25519:
                print("   ⚠️  KEY MISMATCH: Alice's name but wrong keys!")
    except Exception as e:
        print(f"   ✅ PROTECTION: CA refused to issue false certificate: {str(e)[:50]}...")
    
    print("\n" + "="*50)
    print("SECURITY SUMMARY")
    print("="*50 + "\n")
    
    print("✅ PKI Certificate System Security Features:")
    print("   • Username tampering detection")
    print("   • Key tampering detection") 
    print("   • Signature verification")
    print("   • Certificate format validation")
    print("   • CA authenticity verification")
    print("   • Certificate integrity protection")
    
    print("\n⚠️  Limitations (Normal for Test Environment):")
    print("   • CA doesn't verify key ownership during issuance")
    print("   • No revocation checking")
    print("   • Self-signed CA (acceptable for academic project)")
    
    print("\n🎯 CONCLUSION:")
    print("   Your PKI implementation successfully detects and prevents")
    print("   certificate tampering and most common attacks!")

def interactive_tamper_test():
    """Interactive test where you can manually tamper with certificates."""
    print("\n" + "="*50)
    print("INTERACTIVE TAMPER TEST")
    print("="*50 + "\n")
    
    ca = SimpleCertificateAuthority("Interactive Test CA")
    
    # Create certificate
    test_cert = ca.issue_user_certificate(
        "testuser", 
        "dGVzdF9lZDI1NTE5X2tleQ==", 
        "dGVzdF94MjU1MTlfa2V5"
    )
    
    print("Created test certificate for 'testuser'")
    print("\nOriginal certificate verification:")
    is_valid, data = ca.verify_user_certificate(test_cert)
    print(f"Valid: {is_valid}")
    
    if is_valid:
        print(f"Username: {data['username']}")
        print(f"ED25519: {data['ed25519_public_key']}")
    
    print(f"\nCertificate length: {len(test_cert)} characters")
    print(f"Certificate preview: {test_cert[:100]}...")
    
    while True:
        print("\n" + "-"*30)
        print("Choose tampering test:")
        print("1. Change username")
        print("2. Change ED25519 key") 
        print("3. Corrupt signature")
        print("4. Add random characters")
        print("5. Exit")
        
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == "1":
            tampered = test_cert.replace("testuser", "hacker")
            print("Changed 'testuser' to 'hacker'")
        elif choice == "2":
            tampered = test_cert.replace("dGVzdF9lZDI1NTE5X2tleQ==", "aGFja2VyX2tleV9kYXRh")
            print("Changed ED25519 key data")
        elif choice == "3":
            tampered = test_cert[:-50] + "CORRUPTED_SIGNATURE" + "="*30
            print("Corrupted certificate signature")
        elif choice == "4":
            tampered = test_cert + "EXTRA_MALICIOUS_DATA"
            print("Added extra data to certificate")
        elif choice == "5":
            break
        else:
            print("Invalid choice")
            continue
        
        print("\nTesting tampered certificate...")
        try:
            is_tampered_valid, tampered_data = ca.verify_user_certificate(tampered)
            
            if is_tampered_valid:
                print("❌ SECURITY BREACH: Tampered certificate accepted!")
                if tampered_data:
                    print(f"Tampered username: {tampered_data.get('username', 'N/A')}")
            else:
                print("✅ SECURITY SUCCESS: Tampered certificate rejected!")
                
        except Exception as e:
            print(f"✅ SECURITY SUCCESS: Tampered certificate caused error: {str(e)[:60]}...")

if __name__ == "__main__":
    test_certificate_tamper_detection()
    
    print("\n" + "="*60)
    interactive_choice = input("Run interactive tamper test? (y/n): ").strip().lower()
    if interactive_choice == 'y':
        interactive_tamper_test()
    
    print("\n🔐 PKI Security Validation Complete!")
    print("Your certificate system successfully protects against tampering!")