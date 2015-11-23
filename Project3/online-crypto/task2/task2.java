public class task2 {
	static String enumKey(String current) {
        /*Return the next key based on the current key as hex string.
        
        TODO: Implement the required functions.
        */
		return "Your should implement this function! We are going to test it!";
	}

	public static void main (String[] args) {
		String mode = args[0];
		if (mode.equals("enum_key")) {
			System.out.println(enumKey(args[1]));
		} else if (mode.equals("crack")) {
			// TODO: Add your own code and do whatever you do.
		} else {
			System.out.println("Wrong mode!");
		}

	}
}
