import java.security.SecureRandom;

class GenericExceptionsClose{
   public static void main(String args[]){
     try{
         int a[]=new int[7];
         SecureRandom random = new SecureRandom();
         byte bytes[] = new byte[20];
         a[0]=random.nextBytes(bytes);
         a[4]=30/0;
         System.out.println("First print statement in try block");
     }
     catch(ArithmeticException e){
        System.out.println("Warning: ArithmeticException");
     }
     catch(ArrayIndexOutOfBoundsException e){
        System.out.println("Warning: ArrayIndexOutOfBoundsException");
     }
/*
     try {
           System.out.println("Out of try-catch block...");
           int a = Math.random();
  catch(Exception e){
        System.out.println("Warning: Some Other exception");
     }
*/
  }
}
