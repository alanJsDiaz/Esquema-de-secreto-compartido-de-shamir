package mx.unam.criptografia;

import java.io.IOException;

/**
 * Clase principal que ejecuta el programa.
 */
public class Main {
    /**
     * Método principal que ejecuta el programa.
     * @param args Argumentos de la línea de comandos.
     * @throws IOException Si ocurre un error.
     */
    public static void main(String[] args) throws IOException{
        ProcesadorEntrada procesador = new ProcesadorEntrada();
        procesador.procesarEntrada(args);
    }
}
