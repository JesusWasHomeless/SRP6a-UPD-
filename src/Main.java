import javax.naming.InvalidNameException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class Main {

    private static Integer getQ(){
    List<Integer> PrimeList = new ArrayList<>();
    int n = 9999999;
    boolean [] isPrime = new boolean[n];
    isPrime[0]=isPrime[1]=false; //0 i 1 ne prime

        for(int i = 2; i < n; i++){
        isPrime[i] = true; // Пусть все изначально простые
    }
//Если число простое, то любое произведение с ним даёт не простое число, такие отсеиваются
        for(int i = 2; i < isPrime.length; i++){
        if (isPrime[i]){
            for (int j = 2; j*i<isPrime.length; j++){
                isPrime[i*j] = false;
            }
        }
    }

        for (int i = 2; i < n; i++) {
        if (isPrime[i]) {
            PrimeList.add(i);
        }
    }
    Random rnc = new Random();
        for(int i = 0; i < PrimeList.size(); i++)
            if (MillerRabinTest(BigInteger.valueOf(i),5 ))
            return PrimeList.get(rnc.nextInt(PrimeList.size()));
        return null;
}

    public static boolean MillerRabinTest(BigInteger n, int k)
    {
        // если n == 2 или n == 3 - эти числа простые, возвращаем true
        if (n.equals(BigInteger.valueOf(2)) || n.equals(BigInteger.valueOf(3)))
            return true;

        // если n < 2 или n четное - возвращаем false
        if (n.compareTo(BigInteger.valueOf(2)) < 0 || n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))
            return false;

        // представим n ? 1 в виде (2^s)·t, где t нечётно, это можно сделать последовательным делением n - 1 на 2
        BigInteger t = n.subtract(BigInteger.ONE);

        int s = 0;

        while (t.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))

        {
            t = t.divide(BigInteger.valueOf(2));
            s += 1;
        }

        // повторить k раз
        for (int i = 0; i < k; i++) {
            // выберем случайное целое число a в отрезке [2, n ? 2]
            SecureRandom rng = new SecureRandom();

            byte[] _a = new byte[n.toByteArray().length];

            BigInteger a;

            do {
                rng.nextBytes(_a);
                a = new BigInteger(_a);
            }
            while (a.compareTo(BigInteger.valueOf(2)) < 0 || a.compareTo(n.subtract(BigInteger.valueOf(2))) >= 0);

            // x ? a^t mod n, вычислим с помощью возведения в степень по модулю
            BigInteger x = a.modPow(t, n);

            // если x == 1 или x == n ? 1, то перейти на следующую итерацию цикла
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
                continue;

            // повторить s ? 1 раз
            for (int r = 1; r < s; r++) {
                // x ? x^2 mod n
                x = x.modPow(BigInteger.valueOf(2), n);

                // если x == 1, то вернуть "составное"
                if (x.equals(BigInteger.ONE))
                    return false;

                // если x == n ? 1, то перейти на следующую итерацию внешнего цикла
                if (x.equals(n.subtract(BigInteger.ONE)))
                    break;
            }

            if (!Objects.equals(x, n.subtract(BigInteger.ONE)))
                return false;
        }

        // вернуть "вероятно простое"
        return true;
    }
    private static BigInteger getN(){
        BigInteger q = BigInteger.valueOf(Main.getQ());
        BigInteger N_OUT = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);

        return N_OUT;
    }
    public static void main(String[] args) {
        // where g equals
       BigInteger N = getN();
        BigInteger g = BigInteger.valueOf(2);
        // in SRP6a, k = H(N, g)
        BigInteger k = SHA256.hash(N, g);

        Server server = new Server(N, g, k);

        while (true) {
            System.out.println("Войти или зарегистрироваться?");
            System.out.println("1. Зарегистрироваться");
            System.out.println("2. Войти");
            Scanner input = new Scanner(System.in);
            int choice = input.nextInt();
            switch (choice) {
                // Регистрация
                case 1: {
                    System.out.println("Введите логин: ");
                    String login = input.next();

                    System.out.println("Введите пароль: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);

                    client.set_SXV();
                    String s = client.get_s();
                    BigInteger v = client.get_v();
                    try {
                        server.set_ISV(login, s, v);
                        //Если в мапе есть имя, то:
                    } catch (InvalidNameException e) {
                        System.out.println("Имя занято!");
                    }
                    break;
                }
                // Вход
                case 2: {
                    System.out.println("Введите логин: ");
                    String login = input.next();

                    System.out.println("Введите пароль: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);


                    BigInteger A = client.gen_A();
                    try {
                        server.set_A(A);

                    } catch (IllegalAccessException e) {
                        System.out.println("A = 0");
                        break;
                    }

                    try {
                        String s = server.get_s(login);
                        BigInteger B = server.create_B();
                        client.receiveSaltAndB(s, B);
                    } catch (IllegalAccessException e) {
                        System.out.println("Такого пользователя не существует");
                        break;
                    }

                    try {
                        client.gen_u();
                        server.gen_u();
                    } catch (IllegalAccessException e) {
                        System.out.println("Соединение прервано!");
                        break;
                    }

                    client.SessionKey();
                    server.SessionKey();

                    BigInteger server_R = server.create_M(client.ClientConfirm());

                    if (client.compare_R_C(server_R))
                        System.out.println("Соединение установлено");
                    else
                        System.out.println("Неверный пароль");
                    break;
                }
                default:
                    return;
            }
            System.out.println();
        }
    }
}