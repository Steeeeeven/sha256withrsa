import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Main {

    public static void main(String[] args) throws Exception {
        // 生成RSA公钥/私钥:
        //KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        //kpGen.initialize(1024);
        //KeyPair kp = kpGen.generateKeyPair();
        //PrivateKey sk = kp.getPrivate();
        //PublicKey pk = kp.getPublic();
        System.out.println(System.getProperty("java.version"));
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyFactory kf = KeyFactory.getInstance("RSA","BC");
        String privateKey="MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAINdmv+b3U4YUYV4enHxbz/sE+uc\n" +
                "GmK2TkBqtzB5fi9TBIk1SYbuykxtgZf5z16WphaAjoVxyUKJJwuTvVSNvPlW7F1lCXfoojweaXjX\n" +
                "CTWUapg6pYxscnf9N9aVzmZlbMZYTC0yopSC3W9y119sgL/fA7QoxAbUj8lyLDhXzTGLAgMBAAEC\n" +
                "gYALRuvZaY3z+E53QMJyKaG9QQzsuvfg5XmOOhsDxEo60cuf470uIi2npfbsDvvoSNJ1OBAEEKKQ\n" +
                "XanGaqZkLc69EBxRoFry+NPthZDo+3ykj7tn3h9BT0f5+qeMxIR5TQaFeTTFWjuVe9hllKpSfDTo\n" +
                "BW6lkJQWRC/c48dOSv+7sQJBAPP3CC9JSS81CerhRy8TPSh44UWaoXi9iJI/4QNv1M5zkqGmCp+C\n" +
                "YviaGcbq4cc/L83BMqVprA4HDAfU6NYQK8UCQQCJ2JY/pOlL/xAY2Pt9S8lyCwhWjM8rtT3tZtS3\n" +
                "K50US/6rWmSCJ/EiP6Eog/ao1UFU8BmelGDE+y0v6AHGFS0PAkBmzF3PhwLmeGPga+KRzHqFtkG+\n" +
                "EYUemkaU0YPf7dxuzbYolQ1+3vMTK+PWtJxEV7St702G87sDAicomacupAu9AkAJss5nbe/oI+r7\n" +
                "BJE1MJbcyj/s7v1Igvj3cgu3U386xVoGrlZx/eNuWHG7SwWYvWBaXIZA7Qmd8losi7NMP4MrAkEA\n" +
                "gTgDmBVNJMbkhYLATSueJOaS3dW4I6YQ5OsO1pMxNE+Olw4pbxjNDJIQ7UO4y8MOGWDMVkiHYP7c\n" +
                "G6usvijPvw==";
        String publicKey="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDXZr/m91OGFGFeHpx8W8/7BPrnBpitk5Aarcw\n" +
                "eX4vUwSJNUmG7spMbYGX+c9elqYWgI6FcclCiScLk71Ujbz5VuxdZQl36KI8Hml41wk1lGqYOqWM\n" +
                "bHJ3/TfWlc5mZWzGWEwtMqKUgt1vctdfbIC/3wO0KMQG1I/Jciw4V80xiwIDAQAB";



        // 待签名的消息:
        byte[] message = "12321".getBytes();

        // 用私钥签名:
        Signature s = Signature.getInstance("SHA256withRSA");
        byte[]prik= Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs=new PKCS8EncodedKeySpec(prik);
        PrivateKey sk= kf.generatePrivate(pkcs);
        s.initSign(sk);
        s.update(message);
        byte[] signed = s.sign();
        System.out.println("signature: "+Base64.encode(signed));

        // 用公钥验证:
        Signature v = Signature.getInstance("SHA256withRSA");
        byte[]pubk= Base64.decode(publicKey);
        X509EncodedKeySpec pbkcs=new X509EncodedKeySpec(pubk);
        PublicKey pk=kf.generatePublic(pbkcs);
        v.initVerify(pk);
        v.update(message);
        boolean valid = v.verify(signed);
        System.out.println("valid? " + valid);
    }
}
