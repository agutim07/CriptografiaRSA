import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * @author Alberto Gutiérrez Morán
 */

public class Main {
    public static int MOD = 0;

    public static void main(String[] args) {
        //CIFRAMOS EL ALFABETO
        String alf = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNÑOPQRSTUVWXYZáéíóúÁÉÍÓÚ0123456789 ,.:!-¿?()";
        ArrayList<Alfabeto> alfabeto = new ArrayList<>();
        MOD = alf.length();
        for(int i=0; i<alf.length(); i++){
            Alfabeto nuevo = new Alfabeto(alf.charAt(i), i);
            alfabeto.add(nuevo);
        }

        //CLAVE PUBLICA DEL RECEPTOR => 0 = n / 1 = e / 2 = factorizacion de n numero 1 / 3 = fact. de n numero 2
        BigInteger factorizacion[] =  new BigInteger[]{new BigInteger("27264083009"),new BigInteger("27264083017")};
        BigInteger clave[] = new BigInteger[]{new BigInteger("743330222539755158153"),new BigInteger("80263681"),factorizacion[0],factorizacion[1]};

        //TAMAÑO DE BLOQUE DE CIFRADO => K
        int k = getK(clave[0]);

        //CODIFICAMOS EL MENSAJE
//        String msg = "STOP";
//        String msgCodificado = codificarMSG(msg,k,clave,alfabeto);

        //DESCODIFICAMOS EL MENSAJE
        String msgCod = "ñj64Íy l2ÁHxQt0 9 mLP)apHDq,Bc,PÚñl9CíwÍ-WqKzcP éAó2?LuhcaeE2ÉTyúbñ.p:ÑRRGu5hAG:ñÉu8QÚpFfo.F éñBPí5GqW:upAÁZ39víGÓíyCH3.ÉB1XIv1qcMD)Lvr-Rw1L7!-vatA0EQUzr¿o56MfC ()ÉvFrQtbTvdúóÓd)JQjÁi54aáHú1t8ÉGéQÁSLÉ:IGC797:(jÓS8lkYiGQ4ibu¿S6cPjñsñah!kú0EdoYHr8G,í!EÑ?.JH7.EwgñGfuwEJHgFít?AioXÍ!Jq.Xo7SGÓNr.9z4XhJvH1IKxCPlPFsguBRG).YUzM37Un2K2vV?Ir)ñd6UyqóYx3CmDDiDmf:iats)uPÚl1sGñúG0gdGUskajRuJ38:lÓXopipg1GAAwVlékFu:AUqáByFhBLiTkc9!MDuN2YKvIW0A9Í IU7T.QSAjQ?ÑrkáOá6N9(A,Fdñ.RyvrO-wÚ QgíZxp4L-?hJ52Yrvh4a3rB0AéH:é5qwjbYGíHc FTtqúYqR";
        String msgClaro = decodificarMSG(msgCod,k,clave,alfabeto);
        System.out.println(msgClaro);
    }

    private static String codificarMSG(String msg, int k, BigInteger[] clave, ArrayList<Alfabeto> alf){
        BigInteger mod = BigInteger.valueOf(MOD);
        int grupos = msg.length()/k;
        String out = "";

        for(int i=0; i<(grupos*k); i+=k){
            //0. OBTENEMOS EL BLOQUE A CODIFICAR
            String bloque = msg.substring(i,(i+k));
            //1. PASAMOS DE BLOQUE A ENTERO
            int[] codNumerica = new int[k];
            for(int j=0; j<k; j++){codNumerica[j]=getPos(bloque.charAt(j),alf);}
            BigInteger entero = BigInteger.valueOf(0);
            for(int j=0; j<k; j++){
                entero=entero.add(BigInteger.valueOf(codNumerica[j]).multiply(mod.pow(k-j-1)));
            }
            //2. CIFRAMOS CON RSA SIMPLE
            BigInteger cifrado = entero.modPow(clave[1],clave[0]); //entero^e en modulo n
            //3. PASAR DE ENTERO A BLOQUE
            int[] bloquecifradoNum = enteroaBloque(cifrado,k+1);
            String bloquecifrado = "";
            for(int j=0; j<=k; j++){
                bloquecifrado += getChar(bloquecifradoNum[j],alf);
            }
            out+=bloquecifrado;
        }

        return out;
    }

    private static String decodificarMSG(String msg, int k, BigInteger[] clave, ArrayList<Alfabeto> alf){
        BigInteger mod = BigInteger.valueOf(MOD);
        int tam = k+1;
        int grupos = msg.length()/tam;
        String out = "";

        for(int i=0; i<(grupos*tam); i+=tam){
            //1. OBTENEMOS EL BLOQUE A DESCIFRAR
            String bloque = msg.substring(i,(i+tam));
            //2. PASAMOS DE BLOQUE A ENTERO
            int[] codNumerica = new int[tam];
            for(int j=0; j<tam; j++){codNumerica[j]=getPos(bloque.charAt(j),alf);}
            BigInteger entero = BigInteger.valueOf(0);
            for(int j=0; j<tam; j++){
                entero=entero.add(BigInteger.valueOf(codNumerica[j]).multiply(mod.pow(tam-j-1)));
            }
            //3. DESCIFRAMOS EL ENTERO USANDO RSA SIMPLE
            BigInteger newmodulo = (clave[2].subtract(BigInteger.ONE)).multiply(clave[3].subtract(BigInteger.ONE)); //(p-1) * (q-1)
            BigInteger inverso = clave[1].modInverse(newmodulo);    //inverso de e en newmodulo
            BigInteger enteroClaro = entero.modPow(inverso,clave[0]);   // entero^inverso en modulo n
            //4. PASAR EL ENTERO EN CLARO A BLOQUE
            int[] bloquecifradoNum = enteroaBloque(enteroClaro,k);
            String bloquecifrado = "";
            for(int j=0; j<k; j++){
                bloquecifrado += getChar(bloquecifradoNum[j],alf);
            }
            out+=bloquecifrado;
        }

        //SI HAY DOS ESPACIOS SEGUIDOS AÑADIMOS UN SALTO DE LÍNEA
        for(int i=1; i<out.length()-2; i++){
            if(out.charAt(i)==' ' && out.charAt(i-1)==' '){
                out = out.substring(0,i)+'\n'+out.substring(i+1);
            }
        }
        return out;
    }

    private static int getK(BigInteger n){
        BigInteger mod = BigInteger.valueOf(MOD);
        int k = 0;
        BigInteger menor = mod.pow(k); BigInteger mayor = mod.pow(k+1);

        while(menor.compareTo(n)>0 || mayor.compareTo(n)!=1){
            k++;
            menor = mod.pow(k);
            mayor = mod.pow(k+1);
        }

        return k;
    }

    private static int[] enteroaBloque(BigInteger num, int k){
        BigInteger mod = BigInteger.valueOf(MOD);
        int[] bloque = new int[k];
        int pos = k-1;

        while(num.compareTo(BigInteger.ZERO)>0){
            bloque[pos] = num.remainder(mod).intValue();
            pos--;
            num = num.divide(mod);
        }

        for(int i=pos; i>=0; i--){
            bloque[pos] = 0;
        }

        return bloque;
    }

    private static int getPos(char c, ArrayList<Alfabeto> list){
        for(int i=0; i<list.size(); i++){
            if(c==list.get(i).getChar()){
                return list.get(i).getPos();
            }
        }
        return -1;
    }

    private static char getChar(int pos, ArrayList<Alfabeto> list){
        for(int i=0; i<list.size(); i++){
            if(pos==list.get(i).getPos()){
                return list.get(i).getChar();
            }
        }
        return ' ';
    }
}
