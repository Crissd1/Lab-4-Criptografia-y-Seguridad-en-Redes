from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def solicitar_datos():
    clave = input("Ingrese la clave: ").strip()
    iv = input("Ingrese el vector de inicialización (IV): ").strip()
    texto = input("Ingrese el texto a cifrar: ").strip()
    return clave, iv, texto

def ajustar_clave(clave, tamano_necesario):
    clave_bytes = clave.encode('utf-8')
    if len(clave_bytes) < tamano_necesario:         # Completa la clave con bytes aleatorios si es más corta
        clave_bytes += get_random_bytes(tamano_necesario - len(clave_bytes))
    elif len(clave_bytes) > tamano_necesario:        # Trunca la clave si es más larga
        clave_bytes = clave_bytes[:tamano_necesario]
    print(f"Clave ajustada a {tamano_necesario} bytes (hex): {clave_bytes.hex()}")
    return clave_bytes

def ajustar_iv(iv, tamano_necesario):
    iv_bytes = iv.encode('utf-8')
    if len(iv_bytes) < tamano_necesario:        # Completa el IV con bytes aleatorios si es más corto
        iv_bytes += get_random_bytes(tamano_necesario - len(iv_bytes))
    elif len(iv_bytes) > tamano_necesario:        # Trunca el IV si es más largo
        iv_bytes = iv_bytes[:tamano_necesario]
    print(f"IV ajustado a {tamano_necesario} bytes (hex): {iv_bytes.hex()}")
    return iv_bytes

def cifrar_descifrar_DES(texto, clave_bytes, iv_bytes):
    print("\n--- Algoritmo: DES ---")
    
    # Cifrado con DES
    cipher = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_padded = pad(texto.encode('utf-8'), cipher.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")

    # Descifrado con DES
    cipher_dec = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_descifrado_padded = cipher_dec.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, cipher.block_size)
    print(f"Texto descifrado: {texto_descifrado.decode('utf-8')}")

def cifrar_descifrar_3DES(texto, clave_bytes, iv_bytes):
    print("\n--- Algoritmo: 3DES ---")
    
    # Cifrado con 3DES
    cipher = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_padded = pad(texto.encode('utf-8'), cipher.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")

    # Descifrado con 3DES
    cipher_dec = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_descifrado_padded = cipher_dec.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, cipher.block_size)
    print(f"Texto descifrado: {texto_descifrado.decode('utf-8')}")

def cifrar_descifrar_AES256(texto, clave_bytes, iv_bytes):
    print("\n--- Algoritmo: AES-256 ---")
    
    # Cifrado con AES-256
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_padded = pad(texto.encode('utf-8'), cipher.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")

    # Descifrado con AES-256
    cipher_dec = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_descifrado_padded = cipher_dec.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_descifrado_padded, cipher.block_size)
    print(f"Texto descifrado: {texto_descifrado.decode('utf-8')}")

def main():
    clave, iv, texto = solicitar_datos()

    # Ajuste y muestra de clave y IV para cada algoritmo con sus respectivos tamaños
    clave_DES = ajustar_clave(clave, 8)  # 8 bytes para DES
    iv_DES = ajustar_iv(iv, 8)  # 8 bytes para DES
    cifrar_descifrar_DES(texto, clave_DES, iv_DES)

    clave_3DES = ajustar_clave(clave, 24)  # 24 bytes para 3DES
    iv_3DES = ajustar_iv(iv, 8) # 8 bytes para 3DES
    cifrar_descifrar_3DES(texto, clave_3DES, iv_3DES)

    clave_AES = ajustar_clave(clave, 32)  # 32 bytes para AES-256
    iv_AES = ajustar_iv(iv, 16) # 16 bytes para AES-256
    cifrar_descifrar_AES256(texto, clave_AES, iv_AES)

if __name__ == "__main__":
    main()
