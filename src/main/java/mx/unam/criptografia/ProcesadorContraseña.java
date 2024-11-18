package mx.unam.criptografia;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Clase que procesa una contraseña.
 */
public class ProcesadorContraseña {

    /**
     * Obtiene el hash SHA-256 de una contraseña.
     * @param contraseña Contraseña.
     * @return Hash SHA-256 de la contraseña.
     * @throws NoSuchAlgorithmException Si ocurre un error al obtener el hash.
     */
    public static byte[] getSHA256(String contraseña) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(contraseña.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error al obtener el hash SHA-256", e);
        }
    }
}
