package intro_basesdatos_mariadb;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

import at.favre.lib.crypto.bcrypt.BCrypt;

public class UsuariosBD {

    /**
     * Lista los usuarios de la base de datos
     */
    public static void listarUsuarios() {
        Connection conexion = conectar();

        Statement sentencia;
        try {
            sentencia = conexion.createStatement();

            ResultSet resultado = sentencia.executeQuery("SELECT * FROM user");

            while (resultado.next()) {
                // Procesa los datos
                int id = resultado.getInt("id");
                String username = resultado.getString("username");
                String password = resultado.getString("password");
                Timestamp createdAt = resultado.getTimestamp("created_at");

                // Procesa los datos
                System.out.println(
                        "ID: " + id + ", username: " + username + "(" + password + "), createdAt: " + createdAt);
            }

            resultado.close();
            sentencia.close();
            conexion.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Comprueba si un usuario y contraseña son correctos
     * 
     * @param username Usuario
     * @param password Contraseña
     * @return true si el usuario y contraseña son correctos
     */
    public static boolean loginUsuario(String username, String password) {
        boolean loginOk = false;
        Connection conexion = conectar();

        Statement sentencia;
        try {
            sentencia = conexion.createStatement();

            ResultSet resultado = sentencia.executeQuery("SELECT * FROM user WHERE username LIKE '" + username + "'");

            if (resultado.next()) {
                // Si existe el usuario valida la contraseña con BCrypt
                byte[] passwordHashed = resultado.getString("password").getBytes(StandardCharsets.UTF_8);
                BCrypt.Result resultStrict = BCrypt.verifyer(BCrypt.Version.VERSION_2Y).verifyStrict(
                        password.getBytes(StandardCharsets.UTF_8),
                        passwordHashed);
                loginOk = resultStrict.verified;
                loginOk = validarHash2Y(password, resultado.getString("password"));
            }

            resultado.close();
            sentencia.close();
            conexion.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return loginOk;
    }

    /**
     * Cambia la contraseña de un usuario
     * 
     * @param username Usuario
     * @param password Nueva contraseña
     * @return true si se cambió la contraseña
     */
    public static boolean cambiarPassword(String username, String password) {
        boolean cambiarPassword = false;
        Connection conexion = conectar();

        Statement sentencia;
        try {
            sentencia = conexion.createStatement();
            int resultado = sentencia.executeUpdate("UPDATE user SET password='" + generarStringHash2Y(password)
                    + "' WHERE username LIKE '" + username + "'");

            if (resultado == 1) {
                // Si se cambió la contraseña
                cambiarPassword = true;
            }

            sentencia.close();
            conexion.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return cambiarPassword;
    }

    /*
     * FUNCIONES BCRYPT: generar hash y validar hash
     */
    /**
     * Valida un hash de BCrypt
     * 
     * @param password Contraseña en texto claro
     * @param hash2y   Hash de BCrypt
     * @return true si la contraseña es correcta
     */
    private static boolean validarHash2Y(String password, String hash2y) {
        return BCrypt.verifyer(BCrypt.Version.VERSION_2Y)
                .verifyStrict(password.getBytes(StandardCharsets.UTF_8),
                        hash2y.getBytes(StandardCharsets.UTF_8)).verified;
    }

    /**
     * Genera un hash de BCrypt
     * 
     * @param password Contraseña en texto claro
     * @return Hash de BCrypt
     */
    private static String generarStringHash2Y(String password) {
        char[] bcryptChars = BCrypt.with(BCrypt.Version.VERSION_2Y).hashToChar(13, password.toCharArray());
        return String.valueOf(bcryptChars);
    }

    /**
     * Conecta con la base de datos
     * 
     * @return Conexión con la base de datos
     */
    private static Connection conectar() {
        Connection con = null;

        String url = "jdbc:mysql://" + Conexion.HOST + ":" + Conexion.PORT + "/" + Conexion.DATABASE;

        try {
            con = DriverManager.getConnection(url, Conexion.USER, Conexion.PASSWORD);
        } catch (SQLException e) {
            System.out.println("Error al conectar con la BD.");
        }

        return con;
    }

    /**
     * Método principal de ejemplo
     */
    public static void main(String[] args) {
        System.out.println("\n*******************");
        System.out.println("GESTIÓN DE USUARIOS");
        System.out.println("*******************\n");
        System.out.println("BASE DE DATOS: " + Conexion.DATABASE + " en " + Conexion.HOST + ":" + Conexion.PORT);
        System.out.println();

        System.out.println("LISTADO DE USUARIOS:");
        listarUsuarios();
        System.out.println();

        System.out.println("LOGIN DE USUARIO");
        System.out.print("Usuario: ");
        String usuario = System.console().readLine();
        System.out.print("Contraseña: ");
        String password = new String(System.console().readPassword());
        System.out.println(loginUsuario(usuario, password) ? "Login OK" : "Login KO");

        System.out.println("CAMBIO DE CONTRASEÑA");
        System.out.print("Nueva contraseña: ");
        String newPassword = new String(System.console().readPassword());
        System.out.println(
                cambiarPassword(usuario, newPassword) ? "Contraseña cambiada" : "Error al cambiar la contraseña");
    }

}
