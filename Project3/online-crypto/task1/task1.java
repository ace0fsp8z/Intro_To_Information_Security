import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.util.Arrays;


public class task1 {
	public static byte[] cbc_encrypt(byte[] message, byte[] key, byte[] iv) {
		// TODO: Add your code here.
		test();
		return null;
	}

	public static byte[] cbc_decrypt(byte[] message, byte[] key, byte[] iv) {
		// TODO: Add your code here.
		test();
		return null;
	}

	public static void main (String[] args) {
		if (args.length != 5) {
			System.out.println("Wrong number of arguments!\njava task1 $MODE $INFILE $KEYFILE $IVFILE $OUTFILE.");
			System.exit(1);
		} else {
			String mode = args[0];
			String infile = args[1];
			String keyfile = args[2];
			String ivfile = args[3];
			String outfile = args[4];
			byte[] input = readFromFile(infile);
			byte[] key = readFromFile(keyfile);
			byte[] iv = readFromFile(ivfile);
			byte[] output = null;

			double start = getCpuTime();
			// Calculate the CPU cycles.
			if (mode.equals("enc")) {
				output = cbc_encrypt(input, key, iv);
			} else if (mode.equals("dec")) {
				output = cbc_decrypt(input, key, iv);
			} else {
				System.out.println(mode);
				System.out.println("Wrong mode!");
				System.exit(1);
			}
			double end = getCpuTime();
			System.out.printf("Consumed CPU time=%f\n", end - start);
			writeToFile(outfile, output);
		}
	}
    
    static byte[] readFromFile(String path) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(path));
            return encoded;
        } catch (IOException e) {
            System.out.println("File Not Found.");
            return null;
        }
    }
    
    static void writeToFile(String path, byte[] data) {
        try {
            Files.write(Paths.get(path), data);
        } catch (FileNotFoundException e) {
            System.out.println("File Not Found.");
        } catch (IOException e) {
            System.out.println("File Not Found.");
        }
    }

	// Helper functions.
	private static double getCpuTime () {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean();
		// getCurrentThreadCpuTime() returns the total CPU time for the current thread in nanoseconds.
		return bean.isCurrentThreadCpuTimeSupported() ? ((double)bean.getCurrentThreadCpuTime() / 1000000000): 0L;
	}

	static void testDES(String key, String message) {
		DES des = new DES();
		Object k;
		try {
			k = des.makeKey(key.getBytes(), des.KEY_SIZE);
			String output = des.encrypt(k, message.getBytes());
			// suppress output
			//System.out.println(output);
		} catch (InvalidKeyException e) {
			System.out.println("Invalid Key.");
		}
	}
	
	static void test() {
		// This function is for test and illustration purpose.
		char[] chars1 = new char[8];
		char[] chars2 = new char[8];
		Arrays.fill(chars1, '\0');
		Arrays.fill(chars2, '\0');
		String key = new String(chars1);
		String message = new String(chars2);
		testDES(key, message);
		chars2[7] = '\1';
		message = new String(chars2);
		testDES(key, message);
		chars1[7] = '\2';
		chars2[7] = '\0';
		key = new String(chars1);
		message = new String(chars2);
		testDES(key, message);
		chars2[7] = '\1';
		message = new String(chars2);
		testDES(key, message);		
	}
}
