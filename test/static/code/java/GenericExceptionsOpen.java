class GenericExceptionsOpen{
    public static void main(String args[]){
      try{
          int a[]=new int[7];
          a[4]=30/0;
          System.out.println("First print statement in try block");
          if (a[0] > 200) {
              System.out.println("Big num");
          } else  if (a[0] < 100){
              System.out.println("Small num");
          }
      }
      catch(ArithmeticException e){
         System.out.println("Warning: ArithmeticException");
      }
      catch(ArrayIndexOutOfBoundsException e){
         System.out.println("Warning: ArrayIndexOutOfBoundsException");
      }
      catch(Exception e){
         System.out.println("Warning: Some Other exception");
      }
    try {
        System.out.println("Out of try-catch block...");
    }
   catch(Exception e){
         e.printStackTrace();
      }
    }
   }