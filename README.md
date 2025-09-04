# Merkle Trees

Implementación completa de árboles de Merkle con soporte para pruebas de inclusión y no-inclusión, compatible con el algoritmo Bitcoin-style.

## Estructura del Proyecto

```
merkle-trees/
├── src/
│   ├── main.py          # Implementación principal completa
│   ├── hash.py          # Funciones de hash criptográficas  
│   └── base_code.py     # Código base original (referencia)
├── tests/               # Tests unitarios
├── quick_professor_test.py    # Demo rápido de la API
├── test_professor_example.py  # Ejemplos de tests personalizados  
└── README.md           # Este archivo
```

## Implementación

### Requisitos Completados

1. **`generate_proof(hashesOfInterest)`** (4 puntos)
   - Implementa algoritmo Bitcoin-style con recorrido preorder
   - Genera flag bits y hashes mínimos para verificación
   - Maneja duplicación correcta para números impares de elementos

2. **`SortedTree` y `proof_of_non_inclusion()`** (1 punto) 
   - Árbol ordenado lexicográficamente por valor hexadecimal
   - Estrategia por vecinos inmediatos para pruebas eficientes
   - Usa búsqueda binaria O(log n)

3. **`verify_non_inclusion()`** (1 punto)
   - Verifica pruebas de no-inclusión usando inclusión de vecinos
   - Valida ordenamiento estricto y ausencia del elemento target
   - Garantiza seguridad criptográfica

### Clases Principales

```python
class MerkleTree:
    def __init__(self, hashes: List[bytes])
    def generate_proof(self, hashesOfInterest: List[bytes]) -> MerkleProof

class SortedTree(MerkleTree):
    def __init__(self, leaves_hex: List[str])  # Ordena automáticamente
    def proof_of_non_inclusion(self, h: bytes) -> MerkleProof

class MerkleProof:
    hashesOfInterest: List[bytes]  # Elementos objetivo
    nrLeaves: int                  # Tamaño del árbol
    flags: List[int]               # Flag bits para reconstrucción  
    hashes: List[bytes]            # Hashes mínimos necesarios
    meta: dict                     # Metadatos (para no-inclusión)
```

### Algoritmos Implementados

**generate_proof():**
1. Validar que targets están en las hojas del árbol
2. Construir niveles completos del árbol  
3. Marcar subtrees que contienen elementos de interés
4. Recorrido preorder: flag=1 (expandir), flag=0 (incluir hash)

**proof_of_non_inclusion():**  
1. Búsqueda binaria para encontrar posición del elemento ausente
2. Identificar vecinos inmediatos (menor y mayor)
3. Generar pruebas de inclusión para ambos vecinos
4. Concatenar pruebas con metadatos de separación

**verify_non_inclusion():**
1. Separar pruebas concatenadas de los vecinos
2. Verificar que ambos vecinos están incluidos en el árbol
3. Validar ordenamiento estricto: vecino_izq < target < vecino_der

## Tests y Evaluación

### Ejecutar Tests Incluidos

```bash
# Test completo con salida detallada
python3 src/main.py --mode both --verbose

# Solo pruebas de inclusión
python3 src/main.py --mode generated

# Solo pruebas de no-inclusión  
python3 src/main.py --mode noninclusion

# Demo rápido de API (30 segundos)
python3 quick_professor_test.py
```

### Agregar Tests Personalizados  

```python
# Importar API completa
import sys
sys.path.append('src')
from main import MerkleTree, SortedTree, verify_inclusion, verify_non_inclusion

# Test de inclusión personalizado
def test_custom():
    hashes = [bytes.fromhex('aaa...'), bytes.fromhex('bbb...')]
    tree = MerkleTree(hashes)
    proof = tree.generate_proof([hashes[0]])
    assert verify_inclusion([hashes[0]], tree.root, proof)

# Test de no-inclusión personalizado  
def test_non_inclusion():
    sorted_tree = SortedTree(['10', '30', '50'])  # Falta '20'
    absent = bytes.fromhex('20')
    proof = sorted_tree.proof_of_non_inclusion(absent) 
    assert verify_non_inclusion(absent, sorted_tree.root, proof)
```

### Archivos de Ejemplo

- `quick_professor_test.py` - Verificación rápida de que la API funciona
- `test_professor_example.py` - Tests completos con casos extremos

### Para Evaluadores

**Verificación rápida en 3 pasos:**
```bash
# 1. Test básico (30 seg)
python3 src/main.py --mode both

# 2. Demo API (30 seg)  
python3 quick_professor_test.py

# 3. Tests personalizados (usar plantillas arriba)
```

**Especificaciones técnicas:**
- Python 3.7+, sin dependencias externas
- Archivo principal: `src/main.py`
- Hash: SHA-256 compatible con `hash.py`
- Complejidad: O(log n) espacio y verificación

**Consideraciones**

Me ayudé fuertemente de Claude Sonnet 4 para comprender cómo funciona un Merkle Tree y cómo funcionaba una prueba de inclusión y de no inclusión
