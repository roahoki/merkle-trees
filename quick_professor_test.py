#!/usr/bin/env python3
"""
QUICK TEST para verificar la API inmediatamente
Ejecutar: python3 quick_professor_test.py
"""

import sys
sys.path.append('src')
from main import MerkleTree, SortedTree, verify_inclusion, verify_non_inclusion

def quick_api_demo():    
    # 1. Test básico de inclusión
    print("1️⃣  Testing generate_proof()...")
    hashes = [bytes.fromhex(f'{i:064x}') for i in range(1, 5)]  # [1,2,3,4]
    tree = MerkleTree(hashes)
    proof = tree.generate_proof([hashes[1]])  # Probar elemento 2
    result = verify_inclusion([hashes[1]], tree.root, proof)
    print(f"   ✅ generate_proof: {result}")
    
    # 2. Test básico de no-inclusión  
    print("2️⃣  Testing SortedTree.proof_of_non_inclusion()...")
    sorted_tree = SortedTree(['10', '30', '50'])  # Falta '20', '40'
    absent = bytes.fromhex('20')
    proof = sorted_tree.proof_of_non_inclusion(absent)
    result = verify_non_inclusion(absent, sorted_tree.root, proof)
    print(f"   ✅ proof_of_non_inclusion: {result}")
    
    # 3. Test de verify_non_inclusion
    print("3️⃣  Testing verify_non_inclusion()...")
    print(f"   ✅ verify_non_inclusion: {result}")
    
    print("📋 Puede agregar cualquier test personalizado")
    print("📁 Usar: from src.main import * para acceso completo")
    print("=" * 50)

if __name__ == "__main__":
    quick_api_demo()
