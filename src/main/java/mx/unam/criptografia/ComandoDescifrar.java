package mx.unam.criptografia;

/**
 * Comando para descifrar un archivo.
 */
public class ComandoDescifrar implements Comando {
    private String archivoConContraseñasNecesarias;
    private String archivoCifrado;

    /**
     * Constructor.
     * @param archivoConContrasenasNecesarias nombre del archivo con las contraseñas necesarias.
     * @param archivoCifrado nombre del archivo cifrado.
     */
    public ComandoDescifrar(String archivoConContraseñasNecesarias, String archivoCifrado) {
        this.archivoConContraseñasNecesarias = archivoConContraseñasNecesarias;
        this.archivoCifrado = archivoCifrado;
    }

    /**
     * Ejecuta el comando.
     */
    @Override
    public void ejecutar() {
        System.out.println("Descifrando...");
        AES.descifrar(archivoConContraseñasNecesarias, archivoCifrado);
        System.out.println("Archivo Descifrado : " + archivoCifrado );
    }
}
