package gatzi_bmd.newscanner;

import android.Manifest;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import com.ipaulpro.afilechooser.utils.FileUtils;

import android.app.Activity;
import android.content.Intent;
import android.support.v4.app.ActivityCompat;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Base64;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class MainActivity extends Activity implements OnClickListener {
    public TextView  Counter;
    private static final int REQUEST_CHOOSER = 1234;
    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    int itemheigth=0;
    //Itemnames
    ArrayList<String> itemnames = new ArrayList<String>();


    /**
     * ATTENTION: This was auto-generated to implement the App Indexing API.
     * See https://g.co/AppIndexing/AndroidStudio for more information.
     */

    @Override
    protected void onCreate(Bundle savedInstanceState) {


        Button scanBtn;
        Button chooseBtn;
        ImageButton saveBtn;
        ImageButton undoBtn;
        ImageButton emailBtn;
        // Adding items to arrayList
        // Itemnames-old
        /*itemnames.add("Kassen-ID: ");
        itemnames.add("Belegnummer: ");
        itemnames.add("Beleg-Datum: ");
        itemnames.add("Betrag-Satz-Normal: ");
        itemnames.add("Betrag-Satz-Ermaessigt-1: ");
        itemnames.add("Betrag-Satz-Ermaessigt-2: ");
        itemnames.add("Betrag-Satz-Null: ");
        itemnames.add("Betrag-Satz-Besonders: ");
        itemnames.add("Stand-Umsatz-Zaehler-AES256-ICM_");
        itemnames.add("Zertifikat-Seriennummer: ");
        itemnames.add("Sig-Voriger-Beleg: ");
        itemnames.add("Sig-Nächster-Beleg_Calculated: ");
        itemnames.add("Signaturwert: ");
        itemnames.add("Signaturwert: ");
        itemnames.add("Signaturwert: ");*/
        // Itemnames-new
        itemnames.add("Dummy!");
        itemnames.add("Dummy!");
        itemnames.add("KassenID: ");
        itemnames.add("Belegnummer: ");
        itemnames.add("Beleg-Datum: ");
        itemnames.add("Betrag-Normal: ");
        itemnames.add("Betrag-Ermaessigt-1: ");
        itemnames.add("Betrag-Ermaessigt-2: ");
        itemnames.add("Betrag-Null: ");
        itemnames.add("Betrag-Besonders: ");
        itemnames.add("Stand-Umsatz-Zaehler");
        itemnames.add("Zertifikat-Seriennummer: ");
        itemnames.add("Sig-Voriger-Beleg: ");
        itemnames.add("Signaturwert: ");



        int permission = ActivityCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    MainActivity.this,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);


        Counter = (TextView) findViewById(R.id.Counter);
        scanBtn = (Button) findViewById(R.id.scan_button);
        chooseBtn = (Button) findViewById(R.id.choose_button);
        saveBtn = (ImageButton) findViewById(R.id.save_button);
        undoBtn = (ImageButton) findViewById(R.id.undo_button);
        emailBtn = (ImageButton) findViewById(R.id.email_button);
        saveBtn.setOnClickListener(this);
        undoBtn.setOnClickListener(this);
        emailBtn.setOnClickListener(this);
        scanBtn.setOnClickListener(this);
        chooseBtn.setOnClickListener(this);
        try {
            if(savedInstanceState == null) {
                Check_TXT_File();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.scan_button:
                // Setting intent for first button
                Log.i("info", "1. Button Pressed : Start Scanner");
                IntentIntegrator scanIntegrator = new IntentIntegrator(this);
                scanIntegrator.initiateScan();
                break;
            case R.id.choose_button:
                // Setting intent for second button
                Log.i("info", "2. Button Pressed : Start FileChooser");

                Intent getContentIntent = FileUtils.createGetContentIntent();

                Intent intent = Intent.createChooser(getContentIntent, "Select a file");
                startActivityForResult(intent, REQUEST_CHOOSER);

                break;
            case R.id.save_button:
                try {
                    WriteToFile();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                // Setting intent for second button
                Log.i("info", "Save Button Pressed");

                break;
            case R.id.undo_button:
                // Setting intent for second button
                UndoData();
                Log.i("info", "Undo Button Pressed");

                break;
            case R.id.email_button:
                // Setting intent for second button
                EmailData();
                Log.i("info", "Undo Button Pressed");

                break;
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (requestCode!=REQUEST_CHOOSER) {
            IntentResult scanningResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
            if (scanningResult.getContents() != null) {
                String scanContent = scanningResult.getContents();
                String scanFormat = scanningResult.getFormatName();
                TextView formatTxt, KassenID, BelegNr, BelegUhr, BelegNormal, Belegerm1, BelegErm2, BelegNull, BelegBesonder, Umsatzver, Umsatz , Zerti, Sig,Sig2,Signaturwert,Read;
                formatTxt = (TextView) findViewById(R.id.scan_format);
                KassenID = (TextView) findViewById(R.id.Kassen_ID);
                BelegNr = (TextView) findViewById(R.id.Belegnummer);
                BelegUhr = (TextView) findViewById(R.id.Beleg_Datum_Uhrzeit);
                BelegNormal = (TextView) findViewById(R.id.Betrag_Satz_Normal);

                Belegerm1 = (TextView) findViewById(R.id.Betrag_Satz_Ermaessigt_1);
                BelegErm2 = (TextView) findViewById(R.id.Betrag_Satz_Ermaessigt_2);
                BelegNull = (TextView) findViewById(R.id.Betrag_Satz_Null);
                BelegBesonder = (TextView) findViewById(R.id.Betrag_Satz_Besonders);

                Umsatzver = (TextView) findViewById(R.id.Stand_Umsatz_Zaehler_AES256_ICM);
                Umsatz = (TextView) findViewById(R.id.Stand_Umsatz_Zaehler_AES256_ICM_unver);
                Zerti = (TextView) findViewById(R.id.Zertifikat_Seriennummer);
                Sig = (TextView) findViewById(R.id.Sig_Voriger_Beleg);
                Sig2 = (TextView) findViewById(R.id.Sig_Nächster_Beleg);
                Signaturwert = (TextView) findViewById(R.id.Signaturwert);
                Read = (TextView) findViewById(R.id.Read);
                Read.setText("Input : \r\n"+scanContent);
                String ALL=scanContent;
                if (scanContent != null) {
                    String[] separated = scanContent.split("_");
                    if (separated.length >=13) {
                        formatTxt.setText("Input VALID Format: " + scanFormat);
                        String KassenID_alt = "";
                        String BelegID_alt = "";
                        for (int i = 0; i < separated.length; i++) {
                            if (i == 2) {
                                KassenID.setText(itemnames.get(i)+ separated[i]);
                                KassenID_alt = separated[i];
                            }
                            if (i == 3) {
                                BelegNr.setText(itemnames.get(i)+ separated[i]);
                                BelegID_alt = separated[i];
                            }
                            if (i == 4) {
                                BelegUhr.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 5) {
                                BelegNormal.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 6) {
                                Belegerm1.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 7) {
                                BelegErm2.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 8) {
                                BelegNull.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 9) {
                                BelegBesonder.setText(itemnames.get(i) + separated[i]);
                            }
                            if (i == 10) {

                                Umsatzver.setText(itemnames.get(i)+"-ver: " + separated[i]);
                                TextView Path;
                                Path = (TextView) findViewById(R.id.CryptoFile_Path);
                                String Input_path = Path.getText().toString();
                                if(Input_path.equals("")) {
                                    Umsatz.setText(itemnames.get(i)+"-ver: " + separated[i]);
                                    int height = 0; //your textview height
                                    itemheigth = Umsatz.getLayoutParams().height;
                                    Umsatz.getLayoutParams().height = height;
                                }else{
                                    try {
                                        String decryptedTurnOverValue = decryptTurnOverCounterLogic(Input_path, separated[i], KassenID_alt, BelegID_alt);
                                        if(itemheigth>0) {
                                            Umsatz.getLayoutParams().height = itemheigth;
                                        }
                                        Umsatz.setText(itemnames.get(i) + decryptedTurnOverValue);
                                    } catch (Exception e) {
                                        TextView CryptoText;
                                        CryptoText = (TextView) findViewById(R.id.CryptoFile_Path);
                                        CryptoText.setText("ERROR WHILE CALCULATING");
                                        e.printStackTrace();
                                    }

                                }
                            }
                            if (i == 11) {
                                Zerti.setText("Zertifikat-Seriennummer: " + separated[i]);
                            }
                            if (i == 12) {
                                String Try="Error";
                                try {
                                   Try = GenerateJWSSig(ALL);
                                } catch (UnsupportedEncodingException e) {
                                    e.printStackTrace();
                                }
                                MessageDigest md = null;

                                try {
                                    md = MessageDigest.getInstance("sha-256");
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                }

                                // calculate hash value
                                md.update(Try.getBytes());
                                byte[] digest1 = md.digest();
                                // extract number of bytes (N, defined in RKsuite)
                                // from
                                // hash value
                                int bytesToExtract1 = 8;
                                byte[] conDigest1 = new byte[bytesToExtract1];
                                System.arraycopy(digest1, 0, conDigest1, 0, bytesToExtract1);

                                // encode value as BASE64 String ==> chainValue
                                String Sig_Nae_Beleg_String = Base64.encodeToString(conDigest1, Base64.DEFAULT);

                                Sig.setText(itemnames.get(i) + separated[i]);

                                Sig2.setText("Sig-Nächster-Beleg-Calculated: " + Sig_Nae_Beleg_String);
                            }
                            if (i == 13) {
                                Signaturwert.setText(itemnames.get(i) + separated[i]);
                            }
                            if(i==14){
                                while(i<separated.length){
                                    Signaturwert.append("_" + separated[i]);
                                    i++;
                                }
                            }
                        }

                    } else {
                        formatTxt.setText("Input INVALID! Format: " + scanFormat);
                        KassenID.setText("");
                        BelegNr.setText("");
                        BelegUhr.setText("");
                        BelegNormal.setText("");
                        Belegerm1.setText("");
                        BelegErm2.setText("");
                        BelegNull.setText("");
                        Umsatzver.setText("");
                        Signaturwert.setText("");
                        BelegBesonder.setText("");
                        Umsatz.setText("");
                        Zerti.setText("");
                        Sig.setText("");
                        Sig2.setText("");
                    }
                }


            } else {
                Toast toast = Toast.makeText(getApplicationContext(), "No scan data received!", Toast.LENGTH_SHORT);
                toast.show();
            }
        }else if( (requestCode!=REQUEST_EXTERNAL_STORAGE)){
            if (resultCode == RESULT_OK) {

                final Uri uri = intent.getData();

                // Get the File path from the Uri
                String path = FileUtils.getPath(this, uri);

                // Alternatively, use FileUtils.getFile(Context, Uri)
                if (path != null && FileUtils.isLocal(path)) {
                    File file = new File(path);
                    TextView CryptoText;
                    CryptoText = (TextView) findViewById(R.id.CryptoFile_Path);
                    CryptoText.setText(file.getAbsolutePath().toString());
                }
            }
        }
    }

    public static long decryptTurnOverCounter(String encryptedTurnOverCounterBase64, String hashAlgorithm, String cashBoxIDUTF8String, String receiptIdentifierUTF8String, SecretKey aesKey) throws Exception {
        // calc IV value (cashbox if + receipt identifer, both as UTF-8 Strings)
        String IVUTF8StringRepresentation = cashBoxIDUTF8String + receiptIdentifierUTF8String;
        //
        //        // calc hash
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
        byte[] hashValue = messageDigest.digest(IVUTF8StringRepresentation.getBytes());
        byte[] concatenatedHashValue = new byte[16];
        System.arraycopy(hashValue, 0, concatenatedHashValue, 0, 16);

        // extract bytes 0-15 from hash value
        ByteBuffer byteBufferIV = ByteBuffer.allocate(16);
        byteBufferIV.put(concatenatedHashValue);

        // IV for AES algorithm
        byte[] IV = byteBufferIV.array();

        // prepare AES cipher with CTR/ICM mode, NoPadding is essential for the
        // decryption process. Padding could not be reconstructed due
        // to storing only 8 bytes of the cipher text (not the full 16 bytes)
        // (or 5 bytes if the minimum turnover length is used)
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        // start decryption process
        ByteBuffer encryptedTurnOverValueComplete = ByteBuffer.allocate(16);

        // decode turnover base64 value

        byte[] encryptedTurnOverValue = base64Decode(encryptedTurnOverCounterBase64, false);

        // extract length (required to extract the correct number of bytes from
        // decrypted value
        int lengthOfEncryptedTurnOverValue = encryptedTurnOverValue.length;

        // prepare for decryption (require 128 bit blocks...)
        encryptedTurnOverValueComplete.put(encryptedTurnOverValue);
        Security.addProvider(new BouncyCastleProvider());
        // decryption setup, AES ciper in CTR mode, NO PADDING!)
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        // decrypt value, now we have a 128 bit block, with trailing junk bytes
        byte[] testPlainTurnOverValueComplete = cipher.doFinal(encryptedTurnOverValue);

        // remove junk bytes by extracting known length of plain text
        byte[] testPlainTurnOverValue = new byte[lengthOfEncryptedTurnOverValue];
        System.arraycopy(testPlainTurnOverValueComplete, 0, testPlainTurnOverValue, 0, lengthOfEncryptedTurnOverValue);

        // create java LONG out of ByteArray (avoid Error when ByteArray is less then 4)
        return new BigInteger(testPlainTurnOverValue).longValue();
        // Alte Version nicht mehr zulässig !
        /*ByteBuffer plainTurnOverValueByteBuffer = ByteBuffer.wrap(testPlainTurnOverValue);
        if (plainTurnOverValueByteBuffer.remaining() > 4) {
            return plainTurnOverValueByteBuffer.getLong();
        } else {
            long i = 0;
            byte[] test = base64Decode(encryptedTurnOverCounterBase64, false);
            if (test[0] == 83) {
                i = 98989898;
            }
            if (test[0] == 84) {
                i = 97979797;
            }
            return i;
        }*/
    }

    public static byte[] base64Decode(String base64Data, boolean isUrlSafe) throws IOException{
        byte[] data;
        try {

            data = Base64.decode(base64Data, Base64.DEFAULT);

        } catch ( Exception e){
            Log.i("info", "Wrong Crypto File !!!");
            throw new IOException(e.toString());

        }


        return data;
    }

    public void Check_TXT_File() throws IOException {

        File path = MainActivity.this.getExternalFilesDir(null);
        File file1 = new File(path, "SavedData.txt");
        Log.i("info : ","Check the Strorage!");
        if(!file1.exists()){
            file1.createNewFile();
        }
            int length = (int) file1.length();

        byte[] bytes = new byte[length];

        FileInputStream in = new FileInputStream(file1);
        try {
            in.read(bytes);
        } finally {
            in.close();
        }

        String contents = new String(bytes);
        String Test = " \r\n";
        if(contents.equals(Test)){
            Log.i("Text : ", "Text === NULLL");
            Counter.setText("0");
        }else {
            DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    switch (which){
                        case DialogInterface.BUTTON_POSITIVE:
                            File path = MainActivity.this.getExternalFilesDir(null);
                            File file1 = new File(path, "SavedData.txt");
                            int count = 0;

                            try {
                                String OldOne = getStringFromFile(file1.getAbsolutePath());
                                int b = OldOne.indexOf("++++++++++++++++++++++++++++++++++++++++++");


                                while (b != -1) {
                                    count++;
                                    OldOne = OldOne.substring(b + 1);
                                    b = OldOne.indexOf("++++++++++++++++++++++++++++++++++++++++++");
                                }
                            } catch (Exception e) {
                                UpdateCounter(1,"-");
                                e.printStackTrace();
                            }

                            Counter.setText(String.valueOf(count));
                            Log.i("Text : ", "YESSS!!");
                            break;

                        case DialogInterface.BUTTON_NEGATIVE:
                            Counter.setText("0");
                            Log.i("Text : ", "NOOO!");
                            File path2 = MainActivity.this.getExternalFilesDir(null);
                            File file2 = new File(path2, "SavedData.txt");
                            FileOutputStream stream = null;
                            try {
                                stream = new FileOutputStream(file2);
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            }
                            try {
                                stream.write(" \r\n".getBytes());
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                try {
                                    stream.close();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                            break;
                    }
                }
            };
            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
            builder.setCancelable(false);
            builder.setMessage("Want to keep the Old Saved_Files?").setPositiveButton("Yes", dialogClickListener)
                    .setNegativeButton("No", dialogClickListener).show();

        }

    }

    public void WriteToFile() throws Exception {
        File path = MainActivity.this.getExternalFilesDir(null);
        File file1 = new File(path, "SavedData.txt");

        String OldOne = getStringFromFile(file1.getAbsolutePath());

        TextView  KassenID, BelegNr, BelegUhr, BelegNormal, Belegerm1, BelegErm2, BelegNull, BelegBesonder, Umsatzver, Umsatz , Zerti, Sig,Sig2,Signaturwert,Read;
        KassenID = (TextView) findViewById(R.id.Kassen_ID);
        BelegNr = (TextView) findViewById(R.id.Belegnummer);
        BelegUhr = (TextView) findViewById(R.id.Beleg_Datum_Uhrzeit);
        BelegNormal = (TextView) findViewById(R.id.Betrag_Satz_Normal);

        Belegerm1 = (TextView) findViewById(R.id.Betrag_Satz_Ermaessigt_1);
        BelegErm2 = (TextView) findViewById(R.id.Betrag_Satz_Ermaessigt_2);
        BelegNull = (TextView) findViewById(R.id.Betrag_Satz_Null);
        BelegBesonder = (TextView) findViewById(R.id.Betrag_Satz_Besonders);

        Umsatzver = (TextView) findViewById(R.id.Stand_Umsatz_Zaehler_AES256_ICM);
        Umsatz = (TextView) findViewById(R.id.Stand_Umsatz_Zaehler_AES256_ICM_unver);
        Zerti = (TextView) findViewById(R.id.Zertifikat_Seriennummer);
        Sig = (TextView) findViewById(R.id.Sig_Voriger_Beleg);
        Sig2 = (TextView) findViewById(R.id.Sig_Nächster_Beleg);
        Signaturwert = (TextView) findViewById(R.id.Signaturwert);
        Read = (TextView) findViewById(R.id.Read);



        StringBuilder Input = new StringBuilder();
        Input.append(OldOne);
        Input.append("++++++++++++++++++++++++++++++++++++++++++\r\n");
        int newCounter=Integer.parseInt(String.valueOf(Counter.getText()))+1;
        Input.append("QR-Code"+String.valueOf(newCounter)+" am ");
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd_HH:mm :");
        String currentDateAndTime = sdf.format(new Date());
        Input.append(currentDateAndTime+"\r\n");
        Input.append(KassenID.getText()+"\r\n");
        Input.append(BelegNr.getText()+"\r\n");
        Input.append(BelegUhr.getText()+"\r\n");
        Input.append(BelegNormal.getText()+"\r\n");
        Input.append(Belegerm1.getText()+"\r\n");
        Input.append(BelegErm2.getText()+"\r\n");
        Input.append(BelegNull.getText()+"\r\n");
        Input.append(BelegBesonder.getText()+"\r\n");
        Input.append(Umsatzver.getText()+"\r\n");
        //Input.append("");
        Input.append(Umsatz.getText()+"\r\n");
        Input.append(Zerti.getText()+"\r\n");
        Input.append(Sig.getText()+"\r\n");
        Input.append(Sig2.getText()+"\r\n");
        Input.append(Signaturwert.getText()+"\r\n");
        Input.append(Read.getText());



        FileOutputStream stream = null;
        try {
            stream = new FileOutputStream(file1);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            stream.write(Input.toString().getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                stream.close();
                int Testerino =Integer.parseInt(Counter.getText().toString())+1;
                Counter.setText(String.valueOf(Testerino));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public void UndoData() {
        File path = MainActivity.this.getExternalFilesDir(null);
        File file1 = new File(path, "SavedData.txt");

        try {
            String OldOne = getStringFromFile(file1.getAbsolutePath());
            String OldOneOLD = getStringFromFile(file1.getAbsolutePath());
            int b = OldOne.indexOf("++++++++++++++++++++++++++++++++++++++++++");
            String New="";
            int count = 0;
            while (b != -1) {
                count++;
                OldOne = OldOne.substring(b + 1);
                b = OldOne.indexOf("++++++++++++++++++++++++++++++++++++++++++");
                if(b== -1){
                  New= OldOneOLD.replace(OldOne,"");
                }
            }
            New=New.substring(0,New.length()-1);

            FileOutputStream stream = null;
            try {
                stream = new FileOutputStream(file1);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            try {
                stream.write(New.getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    stream.close();
                    int Testerino =Integer.parseInt(Counter.getText().toString())-1;
                    Counter.setText(String.valueOf(Testerino));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void EmailData(){
        File path = MainActivity.this.getExternalFilesDir(null);
        File file = new File(path, "SavedData.txt");
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy_HH:mm");
        String currentDateAndTime = sdf.format(new Date());
        intent.putExtra(Intent.EXTRA_SUBJECT, "QR-Code Input am "+currentDateAndTime);
        intent.putExtra(Intent.EXTRA_TEXT, "Im Anhang");
        if (!file.exists() || !file.canRead()) {
            Toast.makeText(this, "Attachment Error", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        Uri uri = Uri.parse("file://" + file);
        intent.putExtra(Intent.EXTRA_STREAM, uri);
        startActivity(Intent.createChooser(intent, "Send email..."));
    }
    public static String getStringFromFile (String filePath) throws Exception {
        File fl = new File(filePath);
        FileInputStream fin = new FileInputStream(fl);
        String ret = convertStreamToString(fin);
        //Make sure you close all streams.
        fin.close();
        return ret;
    }
    public static String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }
    void UpdateCounter(int count,String Mod) {
        class OneShotTask implements Runnable {
            int count;
            String Mod;
            OneShotTask(int count,String Mod) {}
            public void run() {
                if(Mod=="."){
                    TextView  Counter = (TextView) findViewById(R.id.Counter);
                    setContentView(R.layout.activity_main);
                    Counter.setText(count);
                }
                if(Mod=="+"){
                    TextView  Counter = (TextView) findViewById(R.id.Counter);
                    setContentView(R.layout.activity_main);
                    Counter.setText(Integer.parseInt(Counter.getText().toString())+1);
                }
                if(Mod=="-"){
                    TextView  Counter = (TextView) findViewById(R.id.Counter);
                    setContentView(R.layout.activity_main);
                    Counter.setText("er");
                }
            }
        }
        Thread t = new Thread(new OneShotTask(count,Mod));
        t.start();
    }
    private String GenerateJWSSig(String Payload) throws UnsupportedEncodingException {
        String search="_";
        String jwsSignatureString=Payload.substring(Payload.lastIndexOf(search)+1, Payload.length());
        Payload= Payload.substring(0, Payload.lastIndexOf(search));
        String jwsHeader = "eyJhbGciOiJFUzI1NiJ9";  //ES256 Header for JWS
       // byte[] jwsPayload = Base64.encodeBase64(Payload.getBytes(), true); //get payload
        byte[] data = Payload.getBytes("UTF-8");
        String base64 = Base64.encodeToString(data, Base64.DEFAULT);
        String jwsPayloadString = base64;
        String[] partsString = jwsPayloadString.split("=");
        jwsPayloadString=partsString[0];
        partsString = jwsSignatureString.split("=");
        jwsSignatureString=partsString[0];
        jwsSignatureString=jwsSignatureString.replace('+', '-').replace('/', '_');
        String jwsCompactRep = jwsHeader + "." + jwsPayloadString + "." + jwsSignatureString;
        jwsCompactRep = jwsCompactRep.replace("\n", "").replace("\r", "");
        return jwsCompactRep;
    }
    /*
    * Function: takes CryptoFilePath, Reads in CryptoFile and calculates the decrypted turnovervalue
    *
    *
    *
    *
    *
    *
    * */
    private String decryptTurnOverCounterLogic(String cryptoFilePath, String qRContent, String kassenIDOld,String belegIDOld) throws Exception {
        String encryptedaesKey="";
        if(cryptoFilePath!="") {
            File cryptoFile = new File(cryptoFilePath);
            StringBuilder CryptoFileContent = new StringBuilder();
            BufferedReader cryptoreader = new BufferedReader(new FileReader(cryptoFile));
            String line;
            while ((line = cryptoreader.readLine()) != null) {
                CryptoFileContent.append(line);
            }
            String CryptoFileContentString = CryptoFileContent.toString();
            cryptoreader.close();
            if (isJSONValid(CryptoFileContentString)) {
                encryptedaesKey = new JSONObject(CryptoFileContentString).getString("base64AESKey");
            } else {
                encryptedaesKey = CryptoFileContentString;
            }
            byte[] a = base64Decode(encryptedaesKey, false);
            SecretKey decryptedaesKey = new SecretKeySpec(a, "AES");

            if (qRContent.equals("U1RP")) {
                return "-ver: STO";
            } else if (qRContent.equals("VFJB")) {
                return "-ver: TRA";
            } else {
                long turnOverCounterValue = decryptTurnOverCounter(qRContent, "sha-256", kassenIDOld, belegIDOld, decryptedaesKey);
                double turnOverCounterEuro = (double) turnOverCounterValue;
                turnOverCounterEuro = turnOverCounterEuro / 100;
                return "-unver: " + turnOverCounterEuro + "€";
            }
        }
        else{
            return "";
        }
    }
    public boolean isJSONValid(String totestString) {
        try {
            new JSONObject(totestString);
        } catch (JSONException ex) {
            try {
                new JSONArray(totestString);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }

}
