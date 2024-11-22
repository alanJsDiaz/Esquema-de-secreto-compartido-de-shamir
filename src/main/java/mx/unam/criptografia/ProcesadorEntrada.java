package mx.unam.criptografia;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;

/**
 * Clase que procesa los argumentos de la línea de comandos y ejecuta el comando correspondiente.
 */
public class ProcesadorEntrada {

    /**
     * Procesa los argumentos de la línea de comandos y ejecuta el comando correspondiente.
     * @param args Argumentos de la línea de comandos.
     * @throws NoSuchAlgorithmException 
     */
    public void procesarEntrada(String[] args) throws IOException {
        if (!validarArgumentosSuficientes(args)) {
            return;
        }
        String bandera = args[0];
        try {
            Comando comando = crearComando(bandera, args);
            if (comando != null) {
                comando.ejecutar();
            }
        } catch (IllegalArgumentException | IOException e) {
            imprimirError(e.getMessage());
        }
    }

    /**
     * Valida si los argumentos son suficientes.
     * @param args Argumentos de la línea de comandos.
     * @return true si los argumentos son suficientes, false en caso contrario.
     */
    public boolean validarArgumentosSuficientes(String[] args) {
        if (args.length <= 2) {
            imprimirError("Parámetros insuficientes.");
            mostrarUso();
            return false;
        }
        return true;
    }

    /**
     * Crea el comando correspondiente según la bandera.
     * @param bandera La bandera que indica el tipo de operación (-c o -d).
     * @param args Los argumentos de la línea de comandos.
     * @return El comando a ejecutar, o null si no es válido.
     * @throws IOException Si ocurre un error en la validación de parámetros.
     */
    private Comando crearComando(String bandera, String[] args) throws IOException {
        switch (bandera) {
            case "-c":
            return crearComandoCifrar(args);
            case "-d":
            return crearComandoDescifrar(args);
            default:
            imprimirError("Bandera desconocida.");
            mostrarUso();
            return null;
        }
    }

    /**
     * Crea un comando para cifrar.
     * @param args Argumentos de la línea de comandos.
     * @return El comando para cifrar.
     * @throws IOException Si ocurre un error en la validación de parámetros.
     */
    private Comando crearComandoCifrar(String[] args) throws IOException {
        parametrosValidosCifrar(args);
        String contraseña = pedirContrasena();
        if (contraseña == null) {
            throw new IllegalArgumentException("No se pudo leer la contraseña.");
        }
        byte[] contraseñaProcesada = ProcesadorContraseña.getSHA256(contraseña);
        int numeroTotalEvaluaciones = Integer.parseInt(args[2]);
        int minimoEvaluaciones = Integer.parseInt(args[3]);
        SecretoShamir.archivoConContraseñas(args[1], args[2], args[3], contraseñaProcesada);
        return new ComandoCifrar(args[1], args[4], contraseñaProcesada, numeroTotalEvaluaciones, minimoEvaluaciones);
    }
    

    /**
     * Verifica si los parámetros para cifrar son válidos.
     * @param args Argumentos de la línea de comandos. 
     * @throws IOException Si ocurre un error al leer el archivo.
     */
    private void parametrosValidosCifrar(String[] args) throws IOException {
        if (args.length != 5) {
            throw new IllegalArgumentException("Parámetros insuficientes o demasiados para la bandera -c.");
        }
        archivoValidoContrasenas(args[1]);
        numeroDeEvaluaciones(args[2]);
        numeroMinimoDePuntosValido(args[3], Integer.parseInt(args[2]));
        archivoValidoDocumentoClaro(args[4]);
    }

    /**
     * Verifica si el archivo de texto para guardar las contraseñas es válido.
     * @param archivoConContrasenas Nombre del archivo de texto para guardar las contraseñas.
     */
    private void archivoValidoContrasenas(String archivoConContrasenas) {
        if (archivoConContrasenas.length() > 255) {
            throw new IllegalArgumentException("El nombre del archivo donde se guardaran las contraseñas debe ser menor a 255 caracteres.");
        }
    }

    /**
     * Verifica si el número total de evaluaciones es válido.
     * @param numeroDeEvaluaciones Número total de evaluaciones.
     */
    private void numeroDeEvaluaciones(String numeroDeEvaluaciones) {
        if (!numeroDeEvaluaciones.matches("[0-9.]+")) {
            throw new IllegalArgumentException("El número total de evaluaciones debe ser un número.");
        }
        if (!esEntero(numeroDeEvaluaciones)) {
            throw new IllegalArgumentException("El número total de evaluaciones debe ser un número entero.");
        }
        if (Integer.parseInt(numeroDeEvaluaciones) < 2) {
            throw new IllegalArgumentException("El número total de evaluaciones debe ser mayor a 2.");
        }
    }

    /**
     * Verifica si el número mínimo de puntos es válido.
     * @param numeroMinimoDePuntos Número mínimo de puntos necesarios para descifrar.
     * @param numeroDeContrasenas Número total de contraseñas.
     */
    private void numeroMinimoDePuntosValido(String numeroMinimoDePuntos, int numeroDeEvaluaciones) {
        if (!numeroMinimoDePuntos.matches("[0-9.]+")) {
            throw new IllegalArgumentException("El número mínimo de puntos debe ser un número.");
        } else if (!esEntero(numeroMinimoDePuntos)) {
            throw new IllegalArgumentException("El número mínimo de puntos debe ser un número entero .");
        } else if (Integer.parseInt(numeroMinimoDePuntos) <= 1 || Integer.parseInt(numeroMinimoDePuntos) > numeroDeEvaluaciones) {
            throw new IllegalArgumentException("El número mínimo de evaluaciones debe ser mayor a 1 y menor igual que el numero de contraseñas. Verifica tus datos.");
        }
    }

    /**
     * Verifica si el archivo de texto con el documento claro es válido.
     * @param archivoDocumentoClaro Nombre del archivo de texto con el documento claro.
     * @throws IOException Si ocurre un error al leer el archivo.
     */
    private void archivoValidoDocumentoClaro(String archivoDocumentoClaro) throws IOException {
        if (!new File(archivoDocumentoClaro).exists()) {
            throw new IllegalArgumentException("El documento claro no existe.");
        } else if (!archivoDocumentoClaro.endsWith(".txt")) {
            throw new IllegalArgumentException("El documento claro debe tener extension .txt ");
        } else if (Files.size(new File(archivoDocumentoClaro).toPath()) == 0) {
            throw new IllegalArgumentException("El archivo de texto está vacío.");
        }
    }

    /**
     * Pide una contraseña al usuario sin eco.
     * @return La contraseña ingresada como un String, o null si no se pudo leer.
     */
    private String pedirContrasena() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Error: No se pudo acceder a la consola para leer la contraseña.");
            return null;
        }
        char[] passwordArray = console.readPassword("Introduce la contraseña: ");
        return passwordArray != null ? new String(passwordArray) : null;
    }

    /**
     * Verifica si un String es un número entero.
     * @param input String a verificar.
     * @return true si el String es un número entero, false en otro caso.
     */
    private boolean esEntero(String input) {
        try {
            Integer.parseInt(input);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Crea un comando para descifrar.
     * @param args Argumentos de la línea de comandos.
     * @return El comando para descifrar.
     * @throws IOException Si ocurre un error en la validación de parámetros.
     */
    private Comando crearComandoDescifrar(String[] args) throws IOException {
        parametrosValidosDescifrar(args);
        return new ComandoDescifrar(args[1], args[2]);
    }

    /**
     * Verifica si los parámetros para descifrar son válidos.
     * @param args Argumentos de la línea de comandos.
     * @throws IOException Si ocurre un error al leer el archivo.
     */
    private void parametrosValidosDescifrar(String[] args) throws IOException {
        if (args.length != 3) {
            imprimirError("Parámetros insuficientes o demasiados para la bandera -d.");
            mostrarUso();
            return;
        }
        documentoContreseñasValido(args[1]);
        documentoCifradoValido(args[2], args[1]);
    }

    /**
     * Verifica si el documento con las contraseñas es válido.
     * @param archivoContrasenas Nombre del archivo con las contraseñas.
     * @throws IOException Si ocurre un error al leer el archivo.
     */
    private void documentoContreseñasValido(String archivoContrasenas) throws IOException {
        if (!new File(archivoContrasenas).exists()) {
            throw new IllegalArgumentException("El documento con las contraseñas no existe.");
        } else if (!archivoContrasenas.endsWith(".frg")) {
            throw new IllegalArgumentException("El documento con las contraseñas debe tener extension .frg ");
        } else if (Files.size(new File(archivoContrasenas).toPath()) == 0) {
            throw new IllegalArgumentException("El documento con las contraseñas está vacío.");
        }
    }

    /**
     * Verifica si el documento cifrado es válido.
     * @param archivoCifrado Nombre del archivo cifrado.
     * @param archivoContraseñas Nombre del archivo con las contraseñas.
     * @throws IOException Si ocurre un error al leer el archivo.
     */
    private void documentoCifradoValido(String archivoCifrado, String archivoContraseñas) throws IOException {
        if (!new File(archivoCifrado).exists()) {
            throw new IllegalArgumentException("El documento con las contraseñas no existe.");
        } else if (!archivoCifrado.endsWith(".aes")) {
            throw new IllegalArgumentException("El documento con las contraseñas debe tener extension .aes ");
        } else if (!cadenasIgualesSinUltimosTres(archivoCifrado, archivoContraseñas)) {
            throw new IllegalArgumentException("El nombre del archivo cifrado debe ser igual que el del archivo de las contraseñas, excluyendo la terminacion.");
        } else if (Files.size(new File(archivoCifrado).toPath()) == 0) {
            throw new IllegalArgumentException("El documento con las contraseñas está vacío.");
        }
    }

    /**
     * Verifica si dos cadenas son iguales excluyendo los últimos tres caracteres.
     * @param n cadena 1.
     * @param m cadena 2.
     * @return true si las cadenas son iguales excluyendo los últimos tres caracteres, false en otro caso.
     */
    public boolean cadenasIgualesSinUltimosTres(String n, String m) {
        if (n == null || m == null || n.length() < 3 || m.length() < 3) {
            throw new IllegalArgumentException("Ambas cadenas deben tener al menos 3 caracteres.");
        }
        String subcadenaN = n.substring(0, n.length() - 3);
        String subcadenaM = m.substring(0, m.length() - 3); 
        return subcadenaN.equals(subcadenaM);
    }

    /**
     * Muestra el uso correcto del programa
    */
    private void mostrarUso() {
        System.out.println("Uso:");
        System.out.println("Para Cifrar: -c <Nombre del archivo donde se guardaran las contraseñas> <Número total de contraseñas> <Número minimo de contraseñas para descifrar> <Nombre del archivo con el documento claro>");
        System.out.println("Para Descifrar: -d <archivo_con_contraseñas> <archivo_cifrado>");
    }

    /**
     * Imprime un mensaje de error estandarizado.
     * @param mensaje Mensaje de error a mostrar.
     */
    private void imprimirError(String mensaje) {
        System.out.println("Error: " + mensaje);
    }
}

