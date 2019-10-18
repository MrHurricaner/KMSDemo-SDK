package com.juzix.kms;

public class HexUtil {

	/**
	 * 字节数组转16进制
	 * @param b
	 * @return
	 */
	public static String getHexString(byte[] b) {
		String a = "";
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			a = a + hex;
		}
		return a.toUpperCase();
	}

	public static byte[] hexToByteArray(String hexString) {  
	    if (hexString == null || hexString.equals("")) {  
	        return null;  
	    }  
	    hexString = hexString.toUpperCase();  
	    int length = hexString.length() / 2;
	    char[] hexChars = hexString.toCharArray();  
	    byte[] d = new byte[length];  
	    for (int i = 0; i < length; i++) {  
	        int pos = i * 2;  
	        d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));  
	    }  
	    return d;  
	}
	
	private static byte charToByte(char c) {  
		return (byte) "0123456789ABCDEF".indexOf(c);  
	} 
	
	public static void main(String[] args) {
		String s = "28BF5A13FDAED86AA46E4A3402D0893537EC22050A6002959FDB7EEE1CD7629C2D4361205A4D513C6240D71982379ECE780B90037E3C0B33FFD04ADC6461B535";
		byte [] resultByte = hexToByteArray(s);
		String resultStr = getHexString(resultByte);
		System.out.println(s.equals(resultStr));
	}
}
