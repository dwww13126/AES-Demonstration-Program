import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;

public class AESImageEncryption {
  public static void main(String[] args) {
      if(args.length != 1){
        System.out.println("Error! Please enter a single image file you are wanting to have encrypted");
        System.out.println("E.g java AESImageEncryption ./<ImageName>.bmp");
      }
      else{
        //Creates a new instance of the AES encryption program
        AESImageEncryption c = new AESImageEncryption();
        //Creates the BigInteger keyValue using the given hexidecimal value
        BigInteger keyValue = new BigInteger("770A8A65DA156D24EE2A093277530142", 16);
        //Converts the keyValue into a byte array
        byte[] keyValueBytes = keyValue.toByteArray();
        //Creates a Key using the given keyValue
        Key secKey = new SecretKeySpec(keyValueBytes, "AES");
        //Performs the encryption method through passing in the Key
        //and the file name
        c.setupCyphers(secKey, args[0]);
      }
  }

  //A method which encrypts a given file using Electronic Codebook (ECB), Cipher Block Chaining (CBC)
  //and Cipher Feedback (CFB), outputs the 3 encrypted files
  public void setupCyphers(Key k, String inputFile) {
      try {
          //Trys to open the file
          File imageFile = new File(inputFile);
          //Gets the name of the file without the .bmp extension at the end
          String inputFileN = imageFile.getName();
          int bmpEnd = inputFileN.lastIndexOf(".");
          inputFileN = inputFileN.substring(0, bmpEnd);
          //Sets up each of the names for the output files
          String ECBFileN = "./ECB" + inputFileN + ".jpeg";
          String CBCFileN = "./CBC" + inputFileN + ".jpeg";
          String CFBFileN = "./CFB" + inputFileN + ".jpeg";
          //Configurates the cyphers for each of the
          //ECB, CBC, CFB forms of encryption
          Cipher ECBcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
          Cipher CBCcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          Cipher CFBcipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
          //Sets up a IvParameterSpec for the CBC and CFB
          byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
          IvParameterSpec ivspec = new IvParameterSpec(iv);
          //Sets all the ciphers to use Encrypt mode, passes ivspec for CBC and CFB
          ECBcipher.init(Cipher.ENCRYPT_MODE, k);
          CBCcipher.init(Cipher.ENCRYPT_MODE, k, ivspec);
          CFBcipher.init(Cipher.ENCRYPT_MODE, k, ivspec);
          //Performs the encryptAndOutput method for each of the cipher types
          encryptAndOutput(ECBcipher, inputFile, ECBFileN);
          encryptAndOutput(CBCcipher, inputFile, CBCFileN);
          encryptAndOutput(CFBcipher, inputFile, CFBFileN);
      }
      //Catches any of the exception which could occur during the cypher setup
      //or image reading.
      catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e){
          //Prints out the exception message
          System.out.println(e.getMessage());
      }
    }

    //A method for performing the encryption and the output of the encrypted JEPG's
    public static void encryptAndOutput(Cipher ciphE, String inputBMP, String outputJEPG) {
        try {
            //Create input streams for the encryption input
            FileInputStream inputStreamE = new FileInputStream(inputBMP);
            //Creates a FileOutputStream for the encryption output
            FileOutputStream outputStreamE = new FileOutputStream(outputJEPG);
            //Reads the header info (To prevent corrupt image being output)
            byte[] imageH = new byte[54];
            inputStreamE.read(imageH, 0, 54);
            //Finds the size of the remaining data
            int remaining = inputStreamE.available();
            //Reads the remaining data from the image after the Header
            byte[] imageContent = new byte[remaining];
            inputStreamE.read(imageContent);
            //Performs the encryption on the image data
            byte[] outF = ciphE.doFinal(imageContent);
            //Writes the imageHeader info and the encrypted data
            outputStreamE.write(imageH);
            outputStreamE.write(outF);
            //Closes the Input and Output streams
            inputStreamE.close();
            outputStreamE.flush();
            outputStreamE.close();
        }
        //Catches any of the exception which could occur during encryption or image
        //reading or writing
        catch(BadPaddingException | IllegalBlockSizeException | IOException e){
            //Prints out the exception message
            System.out.println(e.getMessage());
        }
    }
}
