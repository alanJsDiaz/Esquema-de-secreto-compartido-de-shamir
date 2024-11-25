package mx.unam.criptografia;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Clase que implementa el esquema de Shamir para compartir un secreto.
 */
public class SecretoShamir {

    private static final BigInteger modulo = new BigInteger("208351617316091241234326746312124448251235562226470491514186331217050270460481");

    /**
     * Método que escribe un archivo con contraseñas. 
     * @param archivoConContraseñas el nombre del archivo con contraseñas.
     * @param n el número de puntos a generar.
     * @param t el número de puntos necesarios para recuperar el secreto.
     * @param secreto el secreto a compartir.
     */
    public static void archivoConContraseñas(String archivoConContraseñas, String n, String t, byte[] secreto) {
        try {
            archivoConContraseñas = archivoConContraseñas.endsWith(".frg") 
                                    ? archivoConContraseñas 
                                    : archivoConContraseñas + ".frg";
            List<BigInteger> coeficientes = generaPolinomio(Integer.parseInt(t), secreto);
            List<BigInteger[]> puntos = generaPuntos(Integer.parseInt(n), coeficientes);
            String contenido = generarContenidoArchivo(puntos, n, t);
            escribirArchivo(archivoConContraseñas, contenido);
        } catch (IOException e) {
            manejarErrorEscrituraArchivo(e);
        }
    }

    /**
     * Método que genera un polinomio de grado t-1 y el secreto como término independiente.
     * @param t el número de puntos necesarios para recuperar el secreto (con t-1 que sera el grado del polinomio).
     * @param secreto el secreto a compartir.
     * @return Una lista de coeficientes del polinomio.
     */
    public static List<BigInteger> generaPolinomio(int t, byte[] secreto) {
        BigInteger terminoIndependiente = new BigInteger(1, secreto);
        List<BigInteger> coeficientes = new ArrayList<>();
        coeficientes.add(terminoIndependiente);
        SecureRandom random = new SecureRandom();
        for (int i = 1; i < t; i++) {
            coeficientes.add(new BigInteger(128, random));
        }
        return coeficientes;
    }

    /**
     * Método que genera n puntos (x, y) en el plano cartesiano.
     * @param n el número de puntos a generar.
     * @param coeficientes los coeficientes del polinomio.
     * @return una lista de n puntos (x, y).
     */
    public static List<BigInteger[]> generaPuntos(int n, List<BigInteger> coeficientes) {
        Set<BigInteger> valoresX = new HashSet<>();
        List<BigInteger[]> puntos = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        while (puntos.size() < n) {
            BigInteger x = new BigInteger(100, random); 
            if (!valoresX.contains(x)) { 
                valoresX.add(x);
                BigInteger y = evaluaPolinomioHorner(coeficientes, x);
                puntos.add(new BigInteger[]{x, y});
            }
        }
        return puntos;
    }

    /**
     * Método que evalúa un polinomio en un punto x utilizando el algoritmo de Horner.
     * @param coeficientes los coeficientes del polinomio.
     * @param x el punto en el que se evalúa el polinomio.
     * @return el valor del polinomio en el punto x.
     */
    public static BigInteger evaluaPolinomioHorner(List<BigInteger> coeficientes, BigInteger x) {
        BigInteger resultado = BigInteger.ZERO;
        for (int i = coeficientes.size() - 1; i >= 0; i--) {
            resultado = resultado.multiply(x).add(coeficientes.get(i));
        }
        return resultado;
    }

    /**
     * Genera el contenido para el archivo de contraseñas.
     * @param puntos Lista de puntos generados.
     * @param n Número total de contraseñas.
     * @param t Número necesario de contraseñas para descifrar el archivo.
     * @return Contenido del archivo como una cadena de texto.
     */
    private static String generarContenidoArchivo(List<BigInteger[]> puntos, String n, String t) {
        StringBuilder contenido = new StringBuilder();
        for (BigInteger[] punto : puntos) {
            contenido.append(String.format("(%s, %s)%n", punto[0], punto[1]));
        }
        contenido.append(String.format(
            "Numero total de contraseñas: %s%nNumero necesario de contraseñas para descifrar el archivo: %s%n",
            n, t
        ));
        return contenido.toString();
    }

    /**
     * Escribe el contenido en el archivo especificado.
     * @param archivo Nombre del archivo.
     * @param contenido Contenido a escribir.
     * @throws IOException Si ocurre un error durante la escritura.
     */
    private static void escribirArchivo(String archivo, String contenido) throws IOException {
        Files.write(new File(archivo).toPath(), contenido.getBytes());
    }

    /**
     * Maneja los errores que ocurren al escribir el archivo.
     * @param e Excepción lanzada durante la escritura.
     */
    private static void manejarErrorEscrituraArchivo(IOException e) {
        System.err.println("Error al escribir el archivo con contraseñas.");
        e.printStackTrace();
    }

    /**
     * Recupera el secreto a partir de un archivo con contraseñas. 
     * @param archivoConContraseñas el nombre del archivo con contraseñas.
     * @return el secreto recuperado.
     */
    public static byte[] recuperaSecreto(String archivoConContraseñas) {
        List<BigInteger[]> puntos = obtenerPuntos(archivoConContraseñas);
        int t = obtenerTDesdeArchivo(archivoConContraseñas); // Cambiar esta línea
        if (puntos.size() < t) {
            throw new IllegalArgumentException("El número de puntos no coincide con el número necesario de contraseñas.");
        }
        BigInteger secreto = BigInteger.ZERO;
        for (int i = 0; i < puntos.size(); i++) {
            BigInteger yi = puntos.get(i)[1];
            BigInteger li = calcularTérminoLagrange(i, puntos);
            secreto = secreto.add(yi.multiply(li).mod(modulo)).mod(modulo);
        }
        return ByteNormalizado(secreto.toByteArray());
    }

    /**
     * Recupera lospuntos a partir de un archivo con contraseñas.
     * @param archivoConContraseñas Nombre del archivo con contraseñas.
     * @return Una lista de puntos (x, y) como BigInteger[].
     */
    public static List<BigInteger[]> obtenerPuntos(String archivoConContraseñas) {
        File archivo = new File(archivoConContraseñas);
        List<BigInteger[]> puntos = new ArrayList<>();
        try {
            List<String> lineas = Files.readAllLines(archivo.toPath());
            for (String linea : lineas) {
                linea = linea.trim(); // Eliminar espacios en blanco
                if (linea.matches("\\(\\d+, \\d+\\)")) { // Validar formato "(x, y)"
                    String[] punto = linea.replace("(", "").replace(")", "").split(", ");
                    BigInteger x = new BigInteger(punto[0]);
                    BigInteger y = new BigInteger(punto[1]);
                    puntos.add(new BigInteger[]{x, y});
                }
            }
            return puntos;
        } catch (IOException e) {
            System.err.println("Error al leer el archivo con evaluaciones.");
            e.printStackTrace();
            return null;
        }
    }

    public static int obtenerTDesdeArchivo(String archivoConContraseñas) {
        File archivo = new File(archivoConContraseñas);
        try {
            List<String> lineas = Files.readAllLines(archivo.toPath());
            // Buscar la línea que contiene el número mínimo de evaluaciones
            for (String linea : lineas) {
                if (linea.startsWith("Numero necesario de contraseñas para descifrar el archivo:")) {
                    // Extraer el valor de t desde la línea
                    String tString = linea.split(":")[1].trim();
                    return Integer.parseInt(tString);
                }
            }
            throw new IllegalArgumentException("No se encontró el valor de t en el archivo.");
        } catch (IOException e) {
            throw new RuntimeException("Error al leer el archivo de contraseñas.", e);
        }
    }
    

    public static int obtenerNDesdeNombre(String archivoConContraseñas) {
        String nombreSinExtension = archivoConContraseñas.replaceAll("\\.frg$", "");
        int indiceGuion = nombreSinExtension.lastIndexOf("-");
        if (indiceGuion == -1) {
            throw new IllegalArgumentException("El nombre del archivo no contiene el numero total de evaluaciones necesarias.");
        }
        String nString = nombreSinExtension.substring(indiceGuion - 1, indiceGuion);
        try {
            return Integer.parseInt(nString);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("El valor de n en el nombre del archivo no es válido.", e);
        }
    }

    /**
     * Calcula el término de Lagrange Li(0) para un punto i dado y una lista de puntos.
     * @param i Índice del punto actual.
     * @param puntos Lista de puntos (x, y).
     * @return Valor de Li(0) como BigInteger.
     */
    public static BigInteger calcularTérminoLagrange(int i, List<BigInteger[]> puntos) {
        BigInteger li = BigInteger.ONE;
        for (int j = 0; j < puntos.size(); j++) {
            if (i != j) {
                BigInteger xi = puntos.get(i)[0];
                BigInteger xj = puntos.get(j)[0];
                BigInteger numerador = xj.negate().mod(modulo);
                BigInteger denominador = xi.subtract(xj).mod(modulo);
                BigInteger inversoDenominador = denominador.modInverse(modulo);
                li = li.multiply(numerador).mod(modulo).multiply(inversoDenominador).mod(modulo);
            }
        }
        return li;
    }

    /**
     * Normaliza un arreglo de bytes.
     * @param bytes Arreglo de bytes a normalizar.
     * @return Arreglo de bytes normalizado.
     */
    public static byte[] ByteNormalizado(byte[] bytes) {
        if (bytes.length > 32 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
