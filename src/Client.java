import java.math.BigInteger;
import java.util.Random;

public class Client {
private BigInteger N;   // безопасное простое
private BigInteger g;   // генератор по модулю N
private BigInteger k;   // параметр-множитель
private BigInteger x;   // x = H(s,p)
private BigInteger v;   // v = g^x % n
private BigInteger a;   // секретное число
private BigInteger A;   // ОК клиента
private BigInteger B;   // ОК сервера
private BigInteger u;   // скремблер
private BigInteger K;   // hash for session key
private BigInteger M_C; //
private String I;       // логин
private String p;       // пароль
private String s;       // Соль

public Client(BigInteger N, BigInteger g, BigInteger k, String I, String p) {
        this.N = N;
        this.g = g;
        this.k = k;
        this.I = I;
        this.p = p;
        }
//Шаг 1: Клиент вычисляет соль, x и верификатор
public void set_SXV() {
        s = getSalt();
        // x = H(s, p)
        x = SHA256.hash(s, p);
        // v = g^x mod N
        v = g.modPow(x, N);
        }

private String getSalt() {
final int size = 10;
final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
final Random RANDOM = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; ++i) {
        sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
        }

// Шаг 2: Создаём ОК клиента:
public BigInteger gen_A() {
        // а - большое рандомное число
        a = new BigInteger(1024, new Random());
        // A = g^a % N
        A = g.modPow(a, N);
        return A;
        }
// Получаем ОК сервера
public void receiveSaltAndB(String s, BigInteger B) throws IllegalAccessException {
       this.s = s;
        this.B = B;
        //B!=0
    if (B.equals(BigInteger.ZERO))
        throw new IllegalAccessException();
        }

//Шаг 3: генерим скремблер из А и Б:
public void gen_u() throws IllegalAccessException {
        // u = H(A, B)
        u = SHA256.hash(A, B);
        // u != 0
        if (u.equals(BigInteger.ZERO))
        throw new IllegalAccessException();
        }
//Шаг 4: генерация ключа сессии по соли и паролю
public void SessionKey() {
        // x = H(s, p)
        x = SHA256.hash(s, p);
        // S = (B - K*(g^x mod N))^(a+u*x)) mod N
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N)))).modPow(a.add(u.multiply(x)), N);
        // K = H(S)
        K = SHA256.hash(S);
        }
//Шаг 5: подтверждение от клиента
public BigInteger ClientConfirm() {
        // M = H(H(N) xor H(g), H(I), s, A, B, K)
        M_C = SHA256.hash(SHA256.hash(N).xor(SHA256.hash(g)), SHA256.hash(I), s, A, B, K);
        return M_C;
        }
// Клиент вычисляет своё R и сравнивает с R сервера
public boolean compare_R_C(BigInteger R_S) {
        // R = H(A, M, K)
        BigInteger R_C = SHA256.hash(A, M_C, K);
        return R_C.equals(R_S);
        }

public String get_s() {
        return s;
        }

public BigInteger get_v() {
        return v;
        }
        }