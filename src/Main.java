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
        isPrime[i] = true; // ����� ��� ���������� �������
    }
//���� ����� �������, �� ����� ������������ � ��� ��� �� ������� �����, ����� �����������
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
        // ���� n == 2 ��� n == 3 - ��� ����� �������, ���������� true
        if (n.equals(BigInteger.valueOf(2)) || n.equals(BigInteger.valueOf(3)))
            return true;

        // ���� n < 2 ��� n ������ - ���������� false
        if (n.compareTo(BigInteger.valueOf(2)) < 0 || n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))
            return false;

        // ���������� n ? 1 � ���� (2^s)�t, ��� t �������, ��� ����� ������� ���������������� �������� n - 1 �� 2
        BigInteger t = n.subtract(BigInteger.ONE);

        int s = 0;

        while (t.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))

        {
            t = t.divide(BigInteger.valueOf(2));
            s += 1;
        }

        // ��������� k ���
        for (int i = 0; i < k; i++) {
            // ������� ��������� ����� ����� a � ������� [2, n ? 2]
            SecureRandom rng = new SecureRandom();

            byte[] _a = new byte[n.toByteArray().length];

            BigInteger a;

            do {
                rng.nextBytes(_a);
                a = new BigInteger(_a);
            }
            while (a.compareTo(BigInteger.valueOf(2)) < 0 || a.compareTo(n.subtract(BigInteger.valueOf(2))) >= 0);

            // x ? a^t mod n, �������� � ������� ���������� � ������� �� ������
            BigInteger x = a.modPow(t, n);

            // ���� x == 1 ��� x == n ? 1, �� ������� �� ��������� �������� �����
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
                continue;

            // ��������� s ? 1 ���
            for (int r = 1; r < s; r++) {
                // x ? x^2 mod n
                x = x.modPow(BigInteger.valueOf(2), n);

                // ���� x == 1, �� ������� "���������"
                if (x.equals(BigInteger.ONE))
                    return false;

                // ���� x == n ? 1, �� ������� �� ��������� �������� �������� �����
                if (x.equals(n.subtract(BigInteger.ONE)))
                    break;
            }

            if (!Objects.equals(x, n.subtract(BigInteger.ONE)))
                return false;
        }

        // ������� "�������� �������"
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
            System.out.println("����� ��� ������������������?");
            System.out.println("1. ������������������");
            System.out.println("2. �����");
            Scanner input = new Scanner(System.in);
            int choice = input.nextInt();
            switch (choice) {
                // �����������
                case 1: {
                    System.out.println("������� �����: ");
                    String login = input.next();

                    System.out.println("������� ������: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);

                    client.set_SXV();
                    String s = client.get_s();
                    BigInteger v = client.get_v();
                    try {
                        server.set_ISV(login, s, v);
                        //���� � ���� ���� ���, ��:
                    } catch (InvalidNameException e) {
                        System.out.println("��� ������!");
                    }
                    break;
                }
                // ����
                case 2: {
                    System.out.println("������� �����: ");
                    String login = input.next();

                    System.out.println("������� ������: ");
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
                        System.out.println("������ ������������ �� ����������");
                        break;
                    }

                    try {
                        client.gen_u();
                        server.gen_u();
                    } catch (IllegalAccessException e) {
                        System.out.println("���������� ��������!");
                        break;
                    }

                    client.SessionKey();
                    server.SessionKey();

                    BigInteger server_R = server.create_M(client.ClientConfirm());

                    if (client.compare_R_C(server_R))
                        System.out.println("���������� �����������");
                    else
                        System.out.println("�������� ������");
                    break;
                }
                default:
                    return;
            }
            System.out.println();
        }
    }
}