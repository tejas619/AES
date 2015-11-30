import java.io.*;
import java.security.SecureRandom;
/**
 *
 * @author Sujay and Tejas
 */
public class AES 
{
    private static byte[][] state = new byte[4][4];
    private static byte[][] keybyte = new byte[4][4];
    private static byte[][] inputbyte = new byte[4][4];
    private static int[] fact = new int[9];
    private static int multfactor = 0;
    private static byte[][] expandedKey = new byte[44][4];  
    private static String encryptedString = new String();
    public static void main(String[] args) throws IOException
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Input the string to be encrypted:");
        String inputString = new String(br.readLine());
        String tempString = new String();
        int convertedString = 0;
        for(int i=0;i<inputString.length();i++)
        {
            char c = inputString.charAt(i);
            convertedString = (int) c;
            tempString = tempString + Integer.toHexString(convertedString);
        	
        }
        System.out.println(tempString.length());
        int pad;
        int s = tempString.length()*4;
        int c = ((tempString.length()*4)/128);
        int upperbound = (c+1)*128;
        if((upperbound - s)%128 != 0)
        {
            pad = (upperbound -s)/8;
            String a = Integer.toHexString(pad);
            for(int i=0;i<pad-1;i++)
            {
                tempString = tempString + "00";
            }
            tempString += "0";
            tempString += a;
        }
        //System.out.println(tempString);
        String input = new String();
        int inputlength = tempString.length();
        SecureRandom randomGenerator = new SecureRandom();
        byte tempk[] = new byte[4];
        for(int i=0;i<4;i++)
        {
         randomGenerator.nextBytes(tempk);
         for(int j=0;j<4;j++)
         {
             keybyte[j][i] = tempk[j];
         }
        }
        System.out.println("Key generated using Random Generator is : "+toHexString(keybyte));
        for(int z=0;z<=inputlength-32;z+=32)
        {
            String t3 = tempString.substring(z, z+32);
            input = t3;
            System.out.println("This is the encryption of part: "+ z);
            inputbyte = toByteArray(input); 
            StringBuffer hexvalue = toHexString(inputbyte);
            System.out.println("The original hex string of the input is\n"+hexvalue);

            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    state[i][j] = 0;
                }
            }
            keyExpansion(keybyte);
            exorState(inputbyte,keybyte);
            System.out.println("--------------------------------------------");
            System.out.println("The initial exor hex string is\n"+toHexString(state));
            byte[][] currentKey = new byte[4][4];
            for(int i=0;i<9;i++)
            {
                System.out.println("This is round number "+i);
                for(int j=0;j<4;j++)
                {
                    for(int k=0;k<4;k++)
                    {
                        byte t = sBox(state[j][k]);
                        state[j][k] = t;
                    }
                }
                System.out.println("The hex string after SBox is "+toHexString(state));
                shiftRows();
                System.out.println("The hex string after shift rows is "+toHexString(state));
                byte[] temp = new byte[4];
                for(int j=0;j<4;j++)
                {
                    for(int k=0;k<4;k++)
                    {
                        temp[k] = state[k][j];
                    }
                    byte[] temp1 = mixColumns(temp);
                    for(int k=0;k<4;k++)
                    {
                        state[k][j] = temp1[k] ;
                    }
                }
                System.out.println("The hex string after mixColumns is "+toHexString(state));
                int l=0;
                for(int j=(i+1)*4;j<((i+1)*4)+4;j++)
                {
                    for(int k=0;k<4;k++)
                    {
                        currentKey[k][l] = expandedKey[j][k];
                    }
                    l++;
                }
                System.out.println("The hex string of currentKey is "+toHexString(currentKey));
                exorState(state,currentKey);
                System.out.println("The hex string after AddRoundKey is "+toHexString(state));
                System.out.println("The "+i+" round hex string is\n"+toHexString(state));
                /////
            }
            System.out.println("This is last round");
            for(int j=0;j<4;j++)
            {
                for(int k=0;k<4;k++)
                {
                    state[j][k] = sBox(state[j][k]);
                }
            }
            shiftRows();
            int l=0;
            for(int i=40;i<44;i++)
            {
                for(int k=0;k<4;k++)
                {
                    currentKey[k][l] = expandedKey[i][k];
                }
                l++;
            }
            exorState(state,currentKey);
            System.out.println("The final round hex string is\n"+toHexString(state));
            encryptedString += toHexString(state);
        }
        System.out.println("This encrypted text for the input is:  " + encryptedString);
        System.out.println("This is the start of decryption");
        System.out.println("--------------------------------------");
        String decryptedString = new String();
        for(int z=0;z<=inputlength-32;z+=32)
        {
            String t3 = encryptedString.substring(z, z+32);
            input = t3;
            System.out.println("This is the decryption of part: "+z);
            inputbyte = toByteArray(input); 
            System.out.println("The byte representation of the input is :");
            displayByte(inputbyte);
            StringBuffer hexvalue = toHexString(inputbyte);
            System.out.println("The decryption original hex string is\n"+hexvalue);
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    state[i][j] = 0;
                }
            }
            byte[][] currentKey = new byte[4][4];
            int l=0;
            for(int i=40;i<44;i++)
            {
                for(int k=0;k<4;k++)
                {
                    currentKey[k][l] = expandedKey[i][k];
                }
                l++;
            }
            exorState(inputbyte,currentKey);
            System.out.println("--------------------------------------------");
            System.out.println("The initial decryption exor hex string is\n"+toHexString(state));
            for(int i=9;i>0;i--)
            {
                System.out.println("This is decryption round number "+i);
                for(int j=0;j<4;j++)
                {
                    for(int k=0;k<4;k++)
                    {
                        byte t = invSBox(state[j][k]);
                        state[j][k] = t;
                    }
                }
            System.out.println("The hex string after Inverse SBox is "+toHexString(state));
            invShiftRows();
            System.out.println("The hex string after Inverse Shift rows is "+toHexString(state));
            l=0;
            for(int j=((i+1)*4)-4;j<(i+1)*4;j++)
            {
                for(int k=0;k<4;k++)
                {
                    currentKey[k][l] = expandedKey[j][k];
                }
                l++;
            }
            System.out.println("The hex string of currentKey is "+toHexString(currentKey));
            exorState(state,currentKey);
            System.out.println("The hex string after (Inverse) AddRoundKey is "+toHexString(state));
            byte[] temp = new byte[4];
            for(int j=0;j<4;j++)
            {
                for(int k=0;k<4;k++)
                {
                    temp[k] = state[k][j];
                }
                byte[] temp1 = invMixColumns(temp);
                for(int k=0;k<4;k++)
                {
                    state[k][j] = temp1[k] ;
                }
            }
            System.out.println("The hex string after Inverse mixColumns is "+toHexString(state));
            System.out.println("The "+i+" round hex string is\n"+toHexString(state));
            }
            System.out.println("This is decryption last round");
            for(int j=0;j<4;j++)
            {
                for(int k=0;k<4;k++)
                {
                    state[j][k] = invSBox(state[j][k]);
                }
            }
            invShiftRows();
            l=0;
            for(int i=0;i<4;i++)
            {
                for(int k=0;k<4;k++)
                {
                    currentKey[k][l] = expandedKey[i][k];
                }
                l++;
            }
            exorState(state,currentKey);
            System.out.println("The final round decrypted hex string is\n"+toHexString(state));
            decryptedString += toHexString(state);
        }
        System.out.println("This decrypted hex string for the input is:  " + decryptedString);
        System.out.println("Checking for Padding...");
        int t =(int)(decryptedString.charAt(decryptedString.length()-1));
        int padding = t-48;
        if(t >= 65)
        {
            padding = 10 + (t-65);
        }
        System.out.println("The value of padding is "+padding);
        int ctr = decryptedString.length()-4;
        int err = 0;
        for(int i=0;i<padding;i++)
        {
            String p = decryptedString.substring(ctr,ctr+2);
            if(p != "00")
                err = 1;
            ctr-=2;
        }
        String finalnew = new String();
        if(err == 0)
        {
            int value;
            for(int i=0;i<decryptedString.length();i+=2)
            {
                value = 0;
                char a = decryptedString.charAt(i);
                char b = decryptedString.charAt(i+1);
                if((int)a >=48 && (int)a <=57)
                {
                    int t1 = (int)a - 48;
                    value = 16*t1;
                }
                else if((int)a >=65 && (int)a <=90)
                {
                    int t1 = (10 + ((int)a - 65));
                    value = 16 * t1;
                }
                if((int)b >=48 && (int)b <=57)
                {
                    int t1 = (int)a - 48;
                    value += t1;
                }
                else if((int)a >=65 && (int)a <=90)
                {
                    int t1 = (10 + ((int)a - 65));
                    value += t1;
                }
                finalnew+=(char)(value);
            }
        }
        else
        {
            String newf = new String();
            newf = decryptedString.substring(0,((decryptedString.length())-(padding*2)));
            int value;
            for(int i=0;i<newf.length()-1;i+=2)
            {
                value = 0;
                char a = newf.charAt(i);
                char b = newf.charAt(i+1);
                if(a >=48 && a <=57)
                {
                    int t1 = a - 48;
                    value = 16*t1;
                }
                else if(a >=65 && a <=90)
                {
                    int t1 = (10 + (a - 65));
                    value = 16 * t1;
                }
                if(b >=48 && b <=57)
                {
                    int t2 = b - 48;
                    value += t2;
                }
                else if(b >=65 && b <=90)
                {
                    int t2 = (10 + (b - 65));
                    value += t2;
                }
                finalnew+=(char)(value);
            }
        }
        System.out.println("The decrypted string after removing padding bits is "+finalnew);
    }
  
    public static void keyExpansion(byte[][] keybyte)
    {
    	byte[] Rcon = new byte[4];
    	int ctr = 1;
    	for(int i=0;i<4;i++)
    	{
    		for(int j=0;j<4;j++)
    		{
    			expandedKey[i][j]=keybyte[j][i];
    		}
    	}
    	for(int i=4;i<44;i++)
    	{
            if((i%4) != 0)
            {
                    for(int j=0;j<4;j++)
                    {
                            expandedKey[i][j] = (byte) (expandedKey[i-1][j] ^ expandedKey[i-4][j]);
                    }
            }
            else
            {
                    int[] xorconstant = {0,0,0,1,1,0,1,1};
                    int[] element = decToBin(ctr);
                    int[] ele1 = new int[8];
                    int[] arr = new int[8];
                    int flag = 0;

                    Rcon[0] = (byte)ctr;
                    Rcon[1] = (byte)0;
                    Rcon[2] = (byte)0;
                    Rcon[3] = (byte)0;
                    byte[] temp = new byte[4];
                    for(int j=0;j<4;j++)
                    {
                        temp[j] = 0;
                    }
                    for(int j=0;j<4;j++)
                    {
                        temp[j] = expandedKey[i-1][j];
                    }
                    for(int j=0;j<4;j++)
                    {
                            expandedKey[i][j] = temp[(j+1)%4];
                    }
                    for(int j=0;j<4;j++)
                    {
                        expandedKey[i][j] = sBox(expandedKey[i][j]);
                    }
                    for(int j=0;j<4;j++)
                    {
                        expandedKey[i][j] = (byte) (expandedKey[i][j] ^ Rcon[j]);
                    }
                    for(int j=0;j<8;j++)
                    { 
                        ele1[j] = element[j+1];
                        arr[j] = element[j+1];
                    }
                    if(ele1[0] == 1)
                    {
                        flag = 1;
                    }
                    for(int j=0;j<7;j++)
                    {
                        ele1[j] = arr[(j+1)];
                    }
                    ele1[7] = 0;
                    if(flag == 1)
                    {
                        for(int j=0;j<8;j++)
                        {
                            ele1[j] = ele1[j] ^ xorconstant[j];
                        }
                    }
                    for(int j=1;j<9;j++)
                    {
                        element[j] = ele1[j-1];
                    }
                    element[0] = 0;
                    byte s = decToByte(element);
                    ctr = s & 0xFF;
                    for(int j=0;j<4;j++)
                    {
                            expandedKey[i][j] = (byte) (expandedKey[i][j] ^ expandedKey[i-4][j]);
                    }
            }     
    	}
    }
    
    public static byte[] mixColumns(byte[] val)
    {
        int temp = 0;
        byte[] finalval = new byte[4];
        for(int i=0;i<4;i++)
        {
            int[] element = new int[9];
            int[] arr = new int[8];
            int[] ele1 = new int[8];
            int[] ele2 = new int[8];
            int[] ele3 = new int[8];
            int[] ele4 = new int[8];
            if(i==0)
            {   
                //first value in nth row
                temp = val[0] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele1[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele1 = mixMultBy2(ele1);
                //second value in nth row
                temp = val[1] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele2[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele2 = mixMultBy2(ele2);
                for(int j=0;j<8;j++)
                {
                    ele2[j] = ele2[j] ^ arr[j];
                }
                //third element of nth row
                temp = val[2] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele3[j] = element[j+1];
                }
                //fourth element of nth row
                temp = val[3] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele4[j] = element[j+1];
                }
            }
            else if(i == 1)
            {
                //1st element
                temp = val[0] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele1[j] = element[j+1];
                }
                //2nd element
                temp = val[1] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele2[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele2 = mixMultBy2(ele2);
                //3rd element
                temp = val[2] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele3[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele3 = mixMultBy2(ele3);
                for(int j=0;j<8;j++)
                {
                    ele3[j] = ele3[j] ^ arr[j];
                }
                //4th element
                temp = val[3] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele4[j] = element[j+1];
                }   
            }
            else if(i == 2)
            {
                //1st element
                temp = val[0] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele1[j] = element[j+1];
                } 
                //2nd element
                temp = val[1] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele2[j] = element[j+1];
                }
                //3rd element
                temp = val[2] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele3[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele3 = mixMultBy2(ele3);
                //4th element
                temp = val[3] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele4[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele4 = mixMultBy2(ele4);
                for(int j=0;j<8;j++)
                {
                    ele4[j] = ele4[j] ^ arr[j];
                }
            }
            else if(i == 3)
            {
                //1st element
                temp = val[0] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele1[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele1 = mixMultBy2(ele1);
                for(int j=0;j<8;j++)
                {
                    ele1[j] = ele1[j] ^ arr[j];
                }
                //2nd element
                temp = val[1] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele2[j] = element[j+1];
                }
                //3rd element
                temp = val[2] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                {
                    ele3[j] = element[j+1];
                }
                //4th element
                temp = val[3] & 0xFF;
                element = decToBin(temp);
                for(int j=0;j<8;j++)
                { 
                    ele4[j] = element[j+1];
                    arr[j] = element[j+1];
                }
                ele4 = mixMultBy2(ele4);
            }
            for(int j=1;j<9;j++)
            {
                element[j] = ele1[j-1] ^ ele2[j-1];
            }
            for(int j=1;j<9;j++)
            {
                element[j] = element[j] ^ ele3[j-1];
            }
            for(int j=1;j<9;j++)
            {
                element[j] = element[j] ^ ele4[j-1];
            }
            byte finalvalue = decToByte(element);
            finalval[i] = finalvalue;
        }
        for(int i=0;i<4;i++)
        {
            val[i] = finalval[i];
        }
        return val;
    }
    
    public static byte[] invMixColumns(byte[] val)
    {
        byte[][] multMatrix= {{(byte)(0x0e), (byte)(0x0b), (byte)(0x0d), (byte)(0x09)},
                                {(byte)(0x09), (byte)(0x0e), (byte)(0x0b), (byte)(0x0d)},
                                {(byte)(0x0d), (byte)(0x09), (byte)(0x0e), (byte)(0x0b)},
                                {(byte)(0x0b), (byte)(0x0d), (byte)(0x09), (byte)(0x0e)}};
        byte[] prod1 = new byte[4];
        byte[] prod2 = new byte[4];
        for(int i=0;i<4;i++)
        {
            prod1[i] = 0;
            prod2[i] = 0;
        }
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                byte t = mixColumnsMult(multMatrix[i][j], val[j]);
                prod1[j] = t;
            }
            for(int k=0;k<4;k++)
            {
                prod2[i] = (byte)(prod1[k] ^ prod2[i]);
            }
        }
        return prod2;
    }
    public static int[] mixMultBy2(int[] ele1)
    {
        int flag = 0;
        int[] arr = new int[8];
        int[] xorconstant = {0,0,0,1,1,0,1,1};
        for(int i=0;i<8;i++)
        {
            arr[i] = ele1[i];
        }
        if(ele1[0] == 1)
        {
           flag = 1;
        }
        for(int j=0;j<7;j++)
        {
           ele1[j] = arr[(j+1)];
        }
        ele1[7] = 0;
        if(flag == 1)
        {
           for(int j=0;j<8;j++)
           {
               ele1[j] = ele1[j] ^ xorconstant[j];
           }
        }
        return ele1;
    }
    public static byte mixColumnsMult(byte m1, byte m2)
    {
        int[] element = new int[9];
        int[] arr = new int[8];
        int[] ele1 = new int[8];
        int multiplier = m1 & 0xFF;
        int multiplicand  = m2 & 0xFF;
        element = decToBin(multiplicand);
        for(int m=0;m<8;m++)
        {
            ele1[m] = element[m+1];
            arr[m] = element[m+1];
        }
        if(multiplier == 14)
        {
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
            ele1 = mixMultBy2(ele1);
        }
        else if(multiplier == 11)
        {
            ele1 = mixMultBy2(ele1);
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
        }
        else if(multiplier == 9)
        {
            ele1 = mixMultBy2(ele1);
            ele1 = mixMultBy2(ele1);
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
        }
        else if(multiplier == 13)
        {
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
            ele1 = mixMultBy2(ele1);
            ele1 = mixMultBy2(ele1);
            for(int j=0;j<8;j++)
            {
                ele1[j] = ele1[j] ^ arr[j];
            }
        }
        for(int i=0;i<8;i++)
        {
            element[i+1] = ele1[i];
        }
        element[0] = 0;
        byte temp = decToByte(element);
        return temp;
    }
    /*private static byte sBox(byte val) {
		// TODO Auto-generated method stub
                  
        int val1 = val & 0xFF;
    	int s1 = val1 /16;
        int s2 = val1%16;
		
		byte S[][] = { {(byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76 },
					   {(byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0, (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0 },
					   {(byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC, (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15 },
					   {(byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75 },
					   {(byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0, (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84 },
					   {(byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B, (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF },
					   {(byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8 },
					   {(byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5, (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2 },
					   {(byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73 },
					   {(byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB },
					   {(byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C, (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79 },
					   {(byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9, (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08 },
					   {(byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6, (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A },
					   {(byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E },
					   {(byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94, (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF },
					   {(byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16 }
		 			 };
		byte sboxresult = S[s1][s2];
		
		return sboxresult;
	}
    */
    public static byte sBox(byte val)
    {
    	byte temp = multInv(val);
        byte value = affineTransform(temp);
        return value;    	
    }
    private static byte invSBox(byte b)
    {
      	byte t = invAffineTransform(b);
      	byte t1 = multInv(t);
        return t1;
    }
    public static byte affineTransform(byte a)
    {
    	int val = a & 0xFF;
    	int b[] = decToBin(val);
    	int c[][] = arrayTranspose(b);
    	int[][] t1 = matrixMul(c);
    	int constant[][]= { {1},
                            {1},
                            {0},
                            {0},
                            {0},
                            {1},
                            {1},
                            {0}};
    	int[][] result = new int[8][1];
    	for(int i=0;i<8;i++)
    	{
    		
    		result[i][0] = constant[i][0] ^ t1[i][0]; 
    	}
        int[] t2 = new int[9];
    	for(int i=0;i<8;i++)
        {
            t2[i+1] = result[7-i][0];
        }
        t2[0] = 0;
    	byte t3 = decToByte(t2);
        return t3;
    }
    
    public static byte invAffineTransform(byte a)
    {
    	int val = a & 0xFF;
    	int b[] = decToBin(val);
    	int c[][] = arrayTranspose(b);
    	int[][] t1 = invMatrixMul(c);
    	int constant[][]= { {1},
                            {0},
                            {1},
                            {0},
                            {0},
                            {0},
                            {0},
                            {0}};
    	int[][] result = new int[8][1];
    	for(int i=0;i<8;i++)
    	{
    		
    		result[i][0] = constant[i][0] ^ t1[i][0];
    	}
        int[] t2 = new int[9];
    	for(int i=0;i<8;i++)
        {
            t2[i+1] = result[7-i][0];
        }
        t2[0] = 0;
    	byte t3 = decToByte(t2);
        return t3;
    }
    
    private static int[][] invMatrixMul(int[][] x)
    {
    	int[][] tempproduct = new int[8][8];
    	int[][] product = new int[8][1];
        for(int i=0;i<8;i++)
        {
            product[i][0] = 0;
        }
    	int[][] A = {{0,0,1,0,0,1,0,1},
                     {1,0,0,1,0,0,1,0},
                     {0,1,0,0,1,0,0,1},
                     {1,0,1,0,0,1,0,0},
                     {0,1,0,1,0,0,1,0},
                     {0,0,1,0,1,0,0,1},
                     {1,0,0,1,0,1,0,0},
                     {0,1,0,0,1,0,1,0}};
    	for(int i=0;i<8;i++)
    	{
            for (int k=0;k<8;k++)
            {
                    tempproduct[i][k] = (A[i][k] * x[8-k][0]);
            }
            for(int k=0;k<8;k++)
            {
                product[i][0] = product[i][0] ^ tempproduct[i][k];
            }
    	}
        return product;
    }
    
    public static int[][] matrixMul(int[][] x)
    {
        int[][] tempproduct = new int[8][8];
    	int[][] product = new int[8][1];
        for(int i=0;i<8;i++)
        {
            product[i][0] = 0;
        }
    	int[][] A = {{1,0,0,0,1,1,1,1},
                     {1,1,0,0,0,1,1,1},
                     {1,1,1,0,0,0,1,1},
                     {1,1,1,1,0,0,0,1},
                     {1,1,1,1,1,0,0,0},
                     {0,1,1,1,1,1,0,0},
                     {0,0,1,1,1,1,1,0},
                     {0,0,0,1,1,1,1,1}};
    	for(int i=0;i<8;i++)
    	{
            for (int k=0;k<8;k++)
            {
                tempproduct[i][k] = (A[i][k] * x[8-k][0]);
            }
            for(int k=0;k<8;k++)
            {
                product[i][0] = product[i][0] ^ tempproduct[i][k];
            }
    	}
	return product;
    }
    public static int[][] arrayTranspose(int[] b)
    {
    	
    	int a[][] = new int [9][1];
    	for(int i=0;i<9;i++)
    	{
            a[i][0] = b[i];
    	}
	return a;	
    }
    public static StringBuffer toHexString(byte[][] array)
    {
        char[] hexarray = "0123456789ABCDEF".toCharArray();
        StringBuffer hexstring = new StringBuffer();
        for ( int j = 0; j < array.length; j++ )
        {
            for(int k=0;k<array.length;k++)
            {
                int v = array[k][j] & 0xFF;
                hexstring.append(hexarray[v >>> 4]);
                hexstring.append(hexarray[v & 0x0F]);                
            }
        }
        return hexstring;
    }
    
    public static byte[][] toByteArray(String s)
    {
        int len = s.length();
        byte[][] data = new byte[len/8][len/8];
        int i=0;
        while(i<len)
        {
            for(int j=0;j<len/8;j++)
            {
                for(int k=0;k<len/8;k++)
                {
                    data[k][j] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
                    i+=2;
                }
            }
        }
        return data;
    }
    
    public static void displayByte(byte[][] inputbyte)
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                System.out.print(inputbyte[i][j]+" ");
            }
            System.out.println();
        }
    }
    
    public static void exorState(byte[][] array1, byte[][] array2)
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                byte a = array1[i][j];
                byte b = array2[i][j];
                state[i][j] = (byte)(a^b);
            }
        }
    }
    
    public static void shiftRows()
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<i;j++)
            {
                byte temp1 = state[i][3];
                state[i][3] = state[i][0];
                byte temp2 = state[i][2];
                state[i][2] = temp1;
                temp1 = state[i][1];
                state[i][1] = temp2;
                state[i][0] = temp1;               
            }
        }
    }
    
    public static void invShiftRows()
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<i;j++)
            {
                byte temp1 = state[i][0];
                state[i][0] = state[i][3];
                byte temp2 = state[i][1];
                state[i][1] = temp1;
                byte temp3 = state[i][2];
                state[i][2] = temp2;
                state[i][3] = temp3;               
            }
        }
    }
    
    public static byte multInv(byte val)
    {
        int remainder[][] = new int [9][9];
        int[] a= new int [9];
    	int quotient[][] = new int [9][9];
    	int aux[][] = new int[9][9];
    	int num = val & 0xFF;
        int temp[] = new int[9];
        for(int i=0;i<9;i++)
        {
            for(int j=0;j<9;j++)
            {
                remainder[i][j] = 1;
                quotient[i][j] = 0;
            }
            fact[i] = 0;
        }
    	remainder[0][0] = 1;
    	remainder[0][1] = 0;
    	remainder[0][2] = 0;
    	remainder[0][3] = 0;
    	remainder[0][4] = 1;
    	remainder[0][5] = 1;
    	remainder[0][6] = 0;
    	remainder[0][7] = 1;
    	remainder[0][8] = 1;
    	remainder[1] = decToBin(num);
    	aux[0][0] = 0;
    	aux[0][1] = 0;
    	aux[0][2] = 0;
    	aux[0][3] = 0;
    	aux[0][4] = 0;
    	aux[0][5] = 0;
    	aux[0][6] = 0;
    	aux[0][7] = 0;
    	aux[0][8] = 0;
    	aux[1][0] = 0;
    	aux[1][1] = 0;
    	aux[1][2] = 0;
    	aux[1][3] = 0;
    	aux[1][4] = 0;
    	aux[1][5] = 0;
    	aux[1][6] = 0;
    	aux[1][7] = 0;
    	aux[1][8] = 1;
    	a[0] = 1;
    	a[1] = 0;
    	a[2] = 1;
    	a[3] = 1;
    	a[4] = 0;
    	a[5] = 0;
    	a[6] = 0;
    	a[7] = 1;
    	a[8] = 1;
    	int n = 1;
    	int flag = 1;
        int lastvalue = 0;
        if(val == 0)
        {
            return 0;
        }
        else if(val == 1)
        {
            return 1;
        }
        else
        {
    	while(true)
    	{
            lastvalue = 0;
            for(int i=0;i<9;i++)
            {
                fact[i] = 0;
            }
            n = n+1;
            for(int l=0;l<9;l++)
            {
                 a[l]= remainder[n-2][l];
            }
            int temp1[] = new int[9];
            for(int i=0;i<9;i++)
            {
                temp1[i] = remainder[n-1][i];
            }
            int[] temporary = polyDiv(temp1, a);
            for(int i=0;i<9;i++)
            {
                remainder[n][i] = temporary[i];
            }
            temp1 = fact;
            for(int i=0;i<9;i++)
            {
                quotient[n][i] = temp1[i];
            }
            for(int l=0;l<9;l++)
            {
                if(l==8)
                {
                    if(quotient[n][l] == 1)
                        lastvalue = 1;
                }
            }
            if(remainder[n][8] == 1)
            {
                quotient[n][8] = 1;
            }    
            int[][] auxsum = new int[9][9];
            for(int g=0;g<9;g++)
            {
                for(int h=0;h<9;h++)
                {
                    auxsum[g][h] = 0;
                }
            }
            int auxcounter = 0;
            for(int m=0;m<8;m++)
            {
                if(quotient[n][m] == 1)
                {
                    multfactor = 8- m;
                    for(int k=0;k<9;k++)     
                    {
                        if(aux[n-1][k] == 1)
                        {
                            if(multfactor>0)
                            {
                                auxsum[auxcounter][k-multfactor] = 1;
                            }
                        }
                    }
                    auxcounter++;
                }	
            }
            if(lastvalue == 1)
            {
                for(int k=0;k<9;k++)
                {
                    auxsum[auxcounter][k] = aux[n-1][k];
                }
                auxcounter++;
            }
            int[] finalauxsum = new int[9];
            for(int g=0;g<9;g++)
            {
                finalauxsum[g] = 0;
            }
            int tempsum[] = new int[9];
            for(int m=0;m<auxcounter;m+=2)
            {
                for(int p=0;p<9;p++)
                {
                    tempsum[p] = auxsum[m][p] ^ auxsum[m+1][p]; 
                }
                int[] tempsum1 = new int[9];
                for(int p=0;p<9;p++)
                {
                    tempsum1[p] = finalauxsum[p] ^ tempsum[p]; 
                }
                for(int g=0;g<9;g++)
                {
                    finalauxsum[g] = tempsum1[g];
                }
            }
            for(int p=0;p<9;p++)
            {
                aux[n][p] = aux[n-2][p] ^ finalauxsum[p]; 
            }
            flag = 1;
            for(int i=0;i<8;i++)
            {
                if(remainder[n][i] == 1)
                {
                    flag = 0;
                    break;
                }
            }
            if(flag == 1)
            {
                break;
            }
    	}
    	byte inv = decToByte(aux[n]);
    	return inv;
        }
    }
    
    public static byte decToByte(int[] a)
    {
    	double val;
    	double sum = 0;
    	for(int i=0;i<9;i++)
    	{
            if(a[i] == 1)
            {
                val = Math.pow((double)2, (double)(8-i));
                sum+=val;
            }
    	}
    	return ((byte)((int)(sum)));
    }
    
    public static int[] polyDiv(int[] rem,int[] a) 
    {
        int ctr = 0;
        int[] ind = new int[9];
        for(int k=0;k<9;k++)
        {
            ind[k] = 10;
            fact[k] = 0;
        }
        int[] b= new int[9];
        int tempmultfactor = 0;
        for(int i=0;i<9;i++)
        {
            b[i]=rem[i];
        }
        int[] temp2 = new int[9];
        while(true)
        {
        int i=0;
    	for(i=0;i<9;i++)
    	{
    		if(rem[i] == 1)
    		{
                    break;
    		}
    	}
    	int j=0;
    	for(j=0;j<9;j++)
    	{
    		if(a[j]==1)
    		{
                    break;
    		}
    	}
    	tempmultfactor = i-j;
        if(tempmultfactor<0)
        {
            break;
        }
        else
        {
            if(tempmultfactor>0)
            {
                multfactor = tempmultfactor;
                for(int k=0;k<9;k++)     
                {
                    if(rem[k] == 1)
                    {
                        rem[k-multfactor] = 1;
                        rem[k] = 0;
                    }
                }
            }
            if(tempmultfactor == 0)
            {
                multfactor = 0;
            }
            for(int k=0;k<9;k++)
            {
                if(a[k] != rem[k])
                {
                    rem[k] = 1;
                }
                else
                {
                    rem[k] = 0;
                }	
            }
            for(int l=0;l<9;l++)
            {
                a[l]=rem[l];
                rem[l] = b[l];
            }
        }
        ind[ctr++] = 8 - multfactor;
        }
        for(int k=0;k<9;k++)
        {
            if(ind[k] != 10)
            {
                fact[ind[k]] = 1;
            }
        }
    	return a;	
    }
    
    public static int[] binaryAdd(int[] a, int[] b)
    {
    	int carry =0;
    	int sum[] = new int[9];
        for(int i=0;i<9;i++)
        {
            sum[i] = 0;
        }
    	for(int i=8;i>=0;i--)
    	{
            if(carry==0)
            {
                    if(a[i] == 0 && b[i] == 0)
                    {
                        sum[i] = 0; 
                    }
                    if((a[i] == 0 && b[i] == 1) || (a[i] == 1 && b[i] == 0))
                    {
                        sum[i] = 1;
                    }
                    if(a[i] == 1 && b[i] == 1)
                    {
                        carry = 1;
                        sum[i] = 0;
                    }
            }
            else if(carry==1)
            {
                    if(a[i] == 0 && b[i] == 0)
                    {
                        sum[i] = 1;
                        carry = 0;
                    }
                    if((a[i] == 0 && b[i] == 1) || (a[i] == 1 && b[i] == 0))
                    {
                        carry = 1;
                        sum[i] = 0;
                    }
                    if(a[i] == 1 && b[i] == 1)
                    {
                        carry = 1;
                        sum[i] = 1;
                    }
            }
    	}
    	return sum;
    }
    
    public static int[] decToBin(int val)
    {
    	int a[] = new int[9];
    	StringBuffer s = new StringBuffer("");
    	while (val>0)
    	{
            s.append(val%2);
            val = val/2;
    	}
        while(s.length()!=9)
        {
            s.append("0");
        }
    	s.reverse();
    	String s1 = s.toString();
    	for(int i=0;i<s1.length();i++)
    	{
    		a[i] = (Character.digit(s.charAt(i),16));
    	}
    	return a;
    }
}
