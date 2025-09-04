#!/usr/bin/env python3
"""
Test de ejemplo para mostrar que se puede agregar tests
"""

import sys
sys.path.append('src')

from main import *

def test_custom_inclusion():
    """Test personalizado de inclusión"""
    print("=== Test Custom Inclusion ===")
    
    # Crear árbol con datos personalizados
    custom_hashes = [
        bytes.fromhex('1111111111111111111111111111111111111111111111111111111111111111'),
        bytes.fromhex('2222222222222222222222222222222222222222222222222222222222222222'),
        bytes.fromhex('3333333333333333333333333333333333333333333333333333333333333333'),
        bytes.fromhex('4444444444444444444444444444444444444444444444444444444444444444'),
        bytes.fromhex('5555555555555555555555555555555555555555555555555555555555555555')
    ]
    
    tree = MerkleTree(custom_hashes)
    
    # Probar elementos específicos
    targets = [custom_hashes[0], custom_hashes[2], custom_hashes[4]]  
    proof = tree.generate_proof(targets)
    
    result = verify_inclusion(targets, tree.root, proof)
    print(f"Inclusion result: {result}")
    print(f"Proof flags: {proof.flags}")
    print(f"Proof hashes count: {len(proof.hashes)}")
    
    assert result == True, "Custom inclusion test failed"
    print("✅ Custom inclusion test PASSED\n")
    return proof

def test_custom_non_inclusion():
    """Test personalizado de no-inclusión"""
    print("=== Test Custom Non-Inclusion ===")
    
    # Crear árbol ordenado con gaps
    elements = ['10', '20', '40', '50', '70']  # Faltan 15, 25, 35, 45, etc.
    sorted_tree = SortedTree(elements)
    
    # Probar elemento ausente
    absent_element = bytes.fromhex('25')  # Entre 20 y 40
    proof = sorted_tree.proof_of_non_inclusion(absent_element)
    
    result = verify_non_inclusion(absent_element, sorted_tree.root, proof)
    print(f"Non-inclusion result: {result}")
    print(f"Left neighbor: {proof.meta.get('left_hex')}")
    print(f"Target: {proof.meta.get('target_hex')}")
    print(f"Right neighbor: {proof.meta.get('right_hex')}")
    
    assert result == True, "Custom non-inclusion test failed"
    print("✅ Custom non-inclusion test PASSED\n")
    return proof

def test_edge_cases():
    """Test casos extremos que el profesor podría probar"""
    print("=== Test Edge Cases ===")
    
    # Caso 1: Árbol con 1 elemento
    single = [bytes.fromhex('aaaa' + '0' * 60)]
    tree1 = MerkleTree(single)
    proof1 = tree1.generate_proof(single)
    result1 = verify_inclusion(single, tree1.root, proof1)
    print(f"Single element tree: {result1}")
    assert result1 == True
    
    # Caso 2: Número impar (requiere duplicación)
    odd_hashes = [bytes.fromhex(f'{i:064x}') for i in [1, 2, 3]]
    tree2 = MerkleTree(odd_hashes)
    proof2 = tree2.generate_proof([odd_hashes[1]])
    result2 = verify_inclusion([odd_hashes[1]], tree2.root, proof2)
    print(f"Odd number tree: {result2}")
    assert result2 == True
    
    print("✅ Edge cases PASSED\n")

if __name__ == "__main__":
    print("🧪 TESTING API PARA EL PROFESOR\n")
    
    test_custom_inclusion()
    test_custom_non_inclusion() 
    test_edge_cases()
    
    print("🎉 TODOS LOS TESTS PERSONALIZADOS PASARON")
