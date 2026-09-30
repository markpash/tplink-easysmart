import com.tplink.smb.easySmartUtility.transfer.of;
import com.tplink.smb.easySmartUtility.transfer.I;
import com.tplink.smb.easySmartUtility.pages.DeviceInfo;
import com.tplink.smb.easySmartUtility.switchParam.SwitchType;
import com.tplink.smb.easySmartUtility.util.From;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.net.*;
import java.util.Arrays;

public class Harness {
    static final String SWITCH_IP = "10.0.0.106";
    static final int SW_PORT = 29808, LOCAL_PORT = 29809;
    static DatagramSocket sock;
    static int seq = 100;
    static byte[] HOST_MAC = new byte[]{0x00,0x11,0x22,0x33,0x44,0x55};
    static byte[] SW_MAC = new byte[6];
    static int TOKEN = 0;
    static boolean VERBOSE = true;

    static void hexdump(String l,byte[] a,int o,int n){StringBuilder sb=new StringBuilder();for(int i=0;i<n;i++)sb.append(String.format("%02x",a[o+i]&255));System.out.println(l+" ("+n+"B): "+sb);}
    static void w2(ByteArrayOutputStream o,int v){o.write((v>>8)&255);o.write(v&255);}
    static void w4(ByteArrayOutputStream o,long v){o.write((int)((v>>24)&255));o.write((int)((v>>16)&255));o.write((int)((v>>8)&255));o.write((int)(v&255));}
    static byte[] tlv(int t,byte[] v){ByteArrayOutputStream o=new ByteArrayOutputStream();w2(o,t);w2(o,v.length);o.write(v,0,v.length);return o.toByteArray();}
    static byte[] cstr(String s){byte[] b=s.getBytes();byte[] r=new byte[b.length+1];System.arraycopy(b,0,r,0,b.length);return r;}
    static byte[] concat(byte[]a,byte[]b){byte[]r=new byte[a.length+b.length];System.arraycopy(a,0,r,0,a.length);System.arraycopy(b,0,r,a.length,b.length);return r;}
    static String hex(byte[] a){StringBuilder sb=new StringBuilder();for(byte x:a)sb.append(String.format("%02x",x&255));return sb.toString();}
    static byte[] packet(int op,byte[] swmac,int token,byte[] payload){
        ByteArrayOutputStream o=new ByteArrayOutputStream();
        o.write(1);o.write(op);o.write(swmac,0,6);o.write(HOST_MAC,0,6);w2(o,seq++);w4(o,0);
        w2(o,32+payload.length+4);w2(o,0);w2(o,0);w2(o,token);w4(o,0);o.write(payload,0,payload.length);
        o.write(0xff);o.write(0xff);o.write(0);o.write(0);return o.toByteArray();
    }
    static void send1(String dst,byte[] plain,boolean session) throws Exception{
        byte[] enc=plain.clone(); if(session) of.V(enc,enc.length); else of.Code(enc,enc.length);
        if(VERBOSE){System.out.println(">>> "+dst+" session="+session);hexdump("  plain",plain,0,plain.length);hexdump("  enc",enc,0,enc.length);}
        sock.send(new DatagramPacket(enc,enc.length,InetAddress.getByName(dst),SW_PORT));
    }
    static byte[] exchange(byte[] plain,boolean session) throws Exception{
        send1(SWITCH_IP,plain,session);
        byte[] best=null; long end=System.currentTimeMillis()+2000;
        while(System.currentTimeMillis()<end){byte[] d=recv();if(d!=null)best=d;}
        return best;
    }
    static byte[] recv(){long end=System.currentTimeMillis()+1200;while(System.currentTimeMillis()<end){byte[]d=recvOnce();if(d!=null)return d;}return null;}
    static byte[] recvOnce(){
        byte[] buf=new byte[4096];DatagramPacket dp=new DatagramPacket(buf,buf.length);
        try{sock.setSoTimeout(300);sock.receive(dp);}catch(Exception e){return null;}
        if(!dp.getAddress().getHostAddress().equals(SWITCH_IP))return null;
        byte[] raw=Arrays.copyOf(buf,dp.getLength());
        byte[] st=raw.clone();of.Code(st,st.length);
        byte[] dec;boolean session;
        if(st.length>=2&&st[0]==1&&st[1]<5){dec=st;session=false;}else{dec=raw.clone();of.V(dec,dec.length);session=true;}
        if(VERBOSE){System.out.println("<<< "+dp.getAddress().getHostAddress()+" session="+session);hexdump("  raw",raw,0,raw.length);hexdump("  dec",dec,0,dec.length);}
        parse(dec);return dec;
    }
    static void parse(byte[] d){
        if(d.length<32)return;
        int op=d[1]&255,err=((d[16]&255)<<24)|((d[17]&255)<<16)|((d[18]&255)<<8)|(d[19]&255),len=((d[20]&255)<<8)|(d[21]&255),tok=((d[26]&255)<<8)|(d[27]&255);
        System.out.println("  HEADER op="+op+" err="+err+" len="+len+" token="+tok+" swmac="+hex(Arrays.copyOfRange(d,2,8)));
        if(op==2||op==4)TOKEN=tok; SW_MAC=Arrays.copyOfRange(d,2,8);
        int n=32;while(n+4<=d.length){int t=((d[n]&255)<<8)|(d[n+1]&255),l=((d[n+2]&255)<<8)|(d[n+3]&255);n+=4;if(t==0xffff&&l==0)break;if(n+l>d.length)break;System.out.println("  TLV type="+t+" len="+l+" val="+hex(Arrays.copyOfRange(d,n,n+l)));n+=l;}
    }
    static int errOf(byte[] d){return d==null?-1:(((d[16]&255)<<24)|((d[17]&255)<<16)|((d[18]&255)<<8)|(d[19]&255));}
    static int opOf(byte[] d){return d==null?-1:(d[1]&255);}
    static String safeBw(){try{return ""+From.bw();}catch(Throwable t){return "exc";}}

    static void forceNatural(){DeviceInfo.setSwitchType(SwitchType.i("TL-SG108E 6.0"));DeviceInfo.setFirmwareVersion("1.0.0 Build 20230218 Rel.50633");}
    static void forceBig(){DeviceInfo.setFirmwareVersion("9.9.9 Build 20990101");for(SwitchType t:SwitchType.ay()){DeviceInfo.setSwitchType(t);try{if(From.bw())return;}catch(Throwable ig){}}}
    static void forceSmall(){DeviceInfo.setFirmwareVersion("1.0.0 Build 20000101");DeviceInfo.setSwitchType(SwitchType.i("TL-SG108E 6.0"));}
    static void newSessionKey(){try{Field f=of.class.getDeclaredField("mu");f.setAccessible(true);f.setBoolean(null,false);}catch(Exception e){} of.Code(new byte[0],0);}

    static int rsaAndProbe(String mode, Runnable setter) throws Exception {
        setter.run(); newSessionKey();
        System.out.println("\n===== MODE "+mode+"  bw="+safeBw()+"  sessionKey='"+of.oo+"' =====");
        byte[] sk=of.oo.getBytes(); byte[] rsa=I.I(sk,sk.length);
        System.out.println("RSA cipher length = "+rsa.length);
        byte[] r=exchange(packet(3,SW_MAC,TOKEN,tlv(528,rsa)),false);
        int e=errOf(r); System.out.println(">> RSA response err="+e+(e==4098?" = 4098 (OK)":""));
        byte[] r2=exchange(packet(1,SW_MAC,TOKEN,tlv(16384,new byte[0])),true);
        System.out.println(">> session-key GET stats: op="+opOf(r2)+" err="+errOf(r2));
        return errOf(r2);
    }

    public static void main(String[] args) throws Exception {
        of.Code(new byte[0],0);
        sock=new DatagramSocket(null); sock.setReuseAddress(true); sock.setBroadcast(true);
        sock.bind(new InetSocketAddress(LOCAL_PORT)); sock.setSoTimeout(600);

        System.out.println("=== DISCOVERY ===");
        for(int i=0;i<6&&hex(SW_MAC).equals("000000000000");i++){exchange(packet(0,new byte[6],0,new byte[0]),false);try{Thread.sleep(600);}catch(Exception e){}}
        System.out.println("SW_MAC="+hex(SW_MAC)+" TOKEN="+TOKEN);
        System.out.println("=== token GET (static) ===");
        exchange(packet(1,SW_MAC,TOKEN,tlv(2305,new byte[0])),false);

        int natural=rsaAndProbe("natural(small,real fw)",Harness::forceNatural);
        int big=rsaAndProbe("forced-2048bit",Harness::forceBig);
        int small=rsaAndProbe("forced-small",Harness::forceSmall);

        String working = natural==0?"natural":big==0?"big":small==0?"small":null;
        System.out.println("\n### WORKING MODE = "+working);

        // Final clean login using the working mode, fresh key
        if(working!=null){
            if(working.equals("big"))forceBig();else if(working.equals("small"))forceSmall();else forceNatural();
            newSessionKey();
            System.out.println("\n===== CLEAN LOGIN, sessionKey='"+of.oo+"' bw="+safeBw()+" =====");
            byte[] sk=of.oo.getBytes(); byte[] rsa=I.I(sk,sk.length);
            byte[] r=exchange(packet(3,SW_MAC,TOKEN,tlv(528,rsa)),false);
            System.out.println(">> RSA err="+errOf(r));
            byte[] login=concat(tlv(512,cstr("admin")),tlv(514,cstr("admin1")));
            r=exchange(packet(3,SW_MAC,TOKEN,login),true);
            System.out.println(">> LOGIN op="+opOf(r)+" err="+errOf(r));
            r=exchange(packet(1,SW_MAC,TOKEN,tlv(16384,new byte[0])),true);
            System.out.println(">> GET stats op="+opOf(r)+" err="+errOf(r));
            r=exchange(packet(1,SW_MAC,TOKEN,tlv(4096,new byte[0])),true);
            System.out.println(">> GET ports op="+opOf(r)+" err="+errOf(r));
        }
        sock.close();
        System.out.println("\n=== harness done ===");
    }
}
