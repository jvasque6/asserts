class GenericExceptionsClose{
   public static void main(String args[]){
     try{
         int a[]=new int[7];
         a[0] = Math.random();
         a[4]=30/0;
         System.out.println("First print statement in try block");
     }
     catch(ArithmeticException e){

     }
     catch(ArrayIndexOutOfBoundsException e){
        // Oneline comment
     }
     catch(Exception e){
        /*
        Multiline comment
        Test
        */
     }
/*
     try {
           System.out.println("Out of try-catch block...");
  catch(Exception e){
        System.out.println("Warning: Some Other exception");
     }
*/
  }
}