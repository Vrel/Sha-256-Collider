package collision;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;

/**
 * Originally written for an assignment in a Cryptography class at 
 * Sacramento State University.
 * 
 * <p>Attempts to find partial hash collisions using SHA2-256. As described 
 * in by the original assignment: 
 * 
 * <p>"Let’s say that X and Y are k-colliding if the last k bytes of 
 * SHA2-256(X) and SHA2-256(Y) are the same. Find a k-collision for the 
 * largest k you can."
 * 
 * <p>Any such collisions that are discovered are automatically written 
 * to a file. For example "Collision_Output_1.txt" would contain the first 
 * occurrence of a k=1 collision. After finding a collision, the search 
 * begins again, looking for a collision that is one higher than the previously 
 * discovered k.
 * 
 * <p>Command-line arguments can be used at startup to configure some options 
 * for the search. The search can be configured to run on 2, 6, or 8-core 
 * processors by passing "-2" "-6" or "-8" as the first argument, respectively. 
 * Separate searches, with unique starting points, will be run independently on 
 * each core, with one reserved for monitoring for successful searches. The 
 * search can also be configured to start searching for a specific k-collision 
 * by passing the desired k (number only, 1-32) as the second argument. For 
 * example, the arguments "-6 7" would utilize 6 processor cores while beginning 
 * the search at k=7. The initial starting point of the search can be configured 
 * by passing an integer (greater than zero) as the third argument. The initial 
 * values used for the search will be shifted by this amount, allowing either 
 * searching from a specific point, or ensuring that new values are used. The 
 * maximum size of the trees (and thus the required memory) can be configured 
 * by passing an integer (greater than zero) as the fourth argument. If no value 
 * is specified, the default is 5 million.
 * 
 * <p>The JVM should be configured to utilize a large amount of memory (for example: 
 * java -Xmx8196M). Any reasonably large tree size will exceed the default maximum 
 * heap size, and the tree size should be as large as the available hardware will 
 * allow.
 * 
 * @author Robert Thompson
 * @since 11-07-2016
 */
public class Collide{
	//---------------------static constants----------------------------
	/**
	 * First of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y1_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x00,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Second of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y2_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x06,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Third of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y3_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x01,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Fourth of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y4_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x02,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Fifth of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y5_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x03,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Sixth of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y6_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x04,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * Seventh of seven available (distinct) 16 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y7_START_16 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00,//6
		0x00,//7
		0x00,//8
		0x00,//9
		0x00,//10
		0x00,//11
		0x00,//12
		0x05,//13
		0x00,//14
		0x00,//15
		0x00 //16
	};
	/**
	 * First of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y1_START_6 = {
		0x00,//1
		0x00,//2
		0x00,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Second of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y2_START_6 = {
		0x00,//1
		0x00,//2
		0x06,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Third of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y3_START_6 = {
		0x00,//1
		0x00,//2
		0x01,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Fourth of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y4_START_6 = {
		0x00,//1
		0x00,//2
		0x02,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Fifth of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y5_START_6 = {
		0x00,//1
		0x00,//2
		0x03,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Sixth of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y6_START_6 = {
		0x00,//1
		0x00,//2
		0x04,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Seventh of seven available (distinct) 6 byte initialization vectors. 
	 * Each thread uses a different initialization vector to ensure that 
	 * they search different value-spaces.
	 */
	public static final byte[] Y7_START_6 = {
		0x00,//1
		0x00,//2
		0x05,//3
		0x00,//4
		0x00,//5
		0x00 //6
	};
	/**
	 * Prefix for output file names.
	 */
	public static final String FILE_NAME = "Collision_Output_";
	
	//---------------------static variables----------------------------
	/**
	 * Holds the X input for a successful collision in thread zero.
	 */
	public static DataWrapper collider0_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread zero.
	 */
	public static DataWrapper collider0_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread one.
	 */
	public static DataWrapper collider1_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread one.
	 */
	public static DataWrapper collider1_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread two.
	 */
	public static DataWrapper collider2_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread two.
	 */
	public static DataWrapper collider2_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread three.
	 */
	public static DataWrapper collider3_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread three.
	 */
	public static DataWrapper collider3_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread four.
	 */
	public static DataWrapper collider4_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread four.
	 */
	public static DataWrapper collider4_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread five.
	 */
	public static DataWrapper collider5_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread five.
	 */
	public static DataWrapper collider5_Y_result = null;
	/**
	 * Holds the X input for a successful collision in thread six.
	 */
	public static DataWrapper collider6_X_result = null;
	/**
	 * Holds the Y input for a successful collision in thread six.
	 */
	public static DataWrapper collider6_Y_result = null;
	
	/**
	 * Number of threads to use.
	 */
	public static int threads = 2;
	/**
	 * The current number of bytes that must be identical to be considered 
	 * a collision.
	 */
	public static int current_k = 1;
	/**
	 * Value to multiply initialization values by in order to shift the 
	 * search space.
	 */
	public static int iv_advance_multiplier = 1;
	/**
	 * Limit on tree size for result storage. When the tree reaches its 
	 * maximum size, subsequent hashes are compared against the full tree 
	 * then discarded.
	 */
	public static int max_tree_size = 5000000;
	
	//---------------------instance constants--------------------------
	//---------------------instance variables--------------------------
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread zero.
	 */
	RunnableCollider collider0;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread one.
	 */
	RunnableCollider collider1;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread two.
	 */
	RunnableCollider collider2;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread three.
	 */
	RunnableCollider collider3;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread four.
	 */
	RunnableCollider collider4;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread five.
	 */
	RunnableCollider collider5;
	/**
	 * Runnable object that performs the hash operations and comparisons 
	 * to be used by thread six.
	 */
	RunnableCollider collider6;
	/**
	 * Thread zero.
	 */
	Thread thread0;
	/**
	 * Thread one.
	 */
	Thread thread1;
	/**
	 * Thread two.
	 */
	Thread thread2;
	/**
	 * Thread three.
	 */
	Thread thread3;
	/**
	 * Thread four.
	 */
	Thread thread4;
	/**
	 * Thread five.
	 */
	Thread thread5;
	/**
	 * Thread six.
	 */
	Thread thread6;
	
	//---------------------constructors--------------------------------
	/**
	 * Creates a new <code>Collide</code> object and initializes all of the necessary 
	 * elements and operations.
	 */
	public Collide(){
		init();
	}//end of constructor
	
	//---------------------instance methods----------------------------
	/**
	 * Initializes the runnable and thread objects based on the number of 
	 * threads being used.
	 */
	private void init(){
		if(threads == 2){
			collider0 = new RunnableCollider(0);
			collider1 = null;
			collider2 = null;
			collider3 = null;
			collider4 = null;
			collider5 = null;
			collider6 = null;
			thread0 = new Thread(collider0);
			thread1 = null;
			thread2 = null;
			thread3 = null;
			thread4 = null;
			thread5 = null;
			thread6 = null;
		}
		else if(threads == 6){
			collider0 = new RunnableCollider(0);
			collider1 = new RunnableCollider(1);
			collider2 = new RunnableCollider(2);
			collider3 = new RunnableCollider(3);
			collider4 = new RunnableCollider(4);
			collider5 = null;
			collider6 = null;
			thread0 = new Thread(collider0);
			thread1 = new Thread(collider1);
			thread2 = new Thread(collider2);
			thread3 = new Thread(collider3);
			thread4 = new Thread(collider4);
			thread5 = null;
			thread6 = null;
		}
		else if(threads == 8){
			collider0 = new RunnableCollider(0);
			collider1 = new RunnableCollider(1);
			collider2 = new RunnableCollider(2);
			collider3 = new RunnableCollider(3);
			collider4 = new RunnableCollider(4);
			collider5 = new RunnableCollider(5);
			collider6 = new RunnableCollider(6);
			thread0 = new Thread(collider0);
			thread1 = new Thread(collider1);
			thread2 = new Thread(collider2);
			thread3 = new Thread(collider3);
			thread4 = new Thread(collider4);
			thread5 = new Thread(collider5);
			thread6 = new Thread(collider6);
		}
	}//end of init method
	
	/**
	 * Starts the operations of each thread and monitors for any thread 
	 * exiting due to successfully finding a collision. When a result is 
	 * found, all other threads are stopped and all runnable objects are 
	 * reset to their initial state to be used in the next run. Finally, 
	 * the thread objects are cleared, the initialization vectors are 
	 * advanced to new values, and memory is released.
	 */
	public void start(){
		boolean running = true;
		if(thread0 != null){
			thread0.start();
		}
		if(thread1 != null){
			thread1.start();
		}
		if(thread2 != null){
			thread2.start();
		}
		if(thread3 != null){
			thread3.start();
		}
		if(thread4 != null){
			thread4.start();
		}
		if(thread5 != null){
			thread5.start();
		}
		if(thread6 != null){
			thread6.start();
		}
		while(running){
			if(thread0 != null && !thread0.isAlive()){
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread1 != null && !thread1.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread2 != null && !thread2.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread3 != null && !thread3.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread4 != null && !thread4.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread5 != null && !thread5.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread6 != null){
					thread6.interrupt();
				}
			}
			else if(thread6 != null && !thread6.isAlive()){
				if(thread0 != null){
					thread0.interrupt();
				}
				if(thread1 != null){
					thread1.interrupt();
				}
				if(thread2 != null){
					thread2.interrupt();
				}
				if(thread3 != null){
					thread3.interrupt();
				}
				if(thread4 != null){
					thread4.interrupt();
				}
				if(thread5 != null){
					thread5.interrupt();
				}
			}
			boolean t0Done = false;
			boolean t1Done = false;
			boolean t2Done = false;
			boolean t3Done = false;
			boolean t4Done = false;
			boolean t5Done = false;
			boolean t6Done = false;
			if(thread0 != null){
				if(!thread0.isAlive()){
					t0Done = true;
				}
			}
			else{
				t0Done = true;
			}
			if(thread1 != null){
				if(!thread1.isAlive()){
					t1Done = true;
				}
			}
			else{
				t1Done = true;
			}
			if(thread2 != null){
				if(!thread2.isAlive()){
					t2Done = true;
				}
			}
			else{
				t2Done = true;
			}
			if(thread3 != null){
				if(!thread3.isAlive()){
					t3Done = true;
				}
			}
			else{
				t3Done = true;
			}
			if(thread4 != null){
				if(!thread4.isAlive()){
					t4Done = true;
				}
			}
			else{
				t4Done = true;
			}
			if(thread5 != null){
				if(!thread5.isAlive()){
					t5Done = true;
				}
			}
			else{
				t5Done = true;
			}
			if(thread6 != null){
				if(!thread6.isAlive()){
					t6Done = true;
				}
			}
			else{
				t6Done = true;
			}
			if(t0Done && t1Done && t2Done && t3Done && t4Done && t5Done && t6Done){
				running = false;
				if(collider0 != null){
					collider0.cleanup();
					collider0 = null;
				}
				if(collider1 != null){
					collider1.cleanup();
					collider1 = null;
				}
				if(collider2 != null){
					collider2.cleanup();
					collider2 = null;
				}
				if(collider3 != null){
					collider3.cleanup();
					collider3 = null;
				}
				if(collider4 != null){
					collider4.cleanup();
					collider4 = null;
				}
				if(collider5 != null){
					collider5.cleanup();
					collider5 = null;
				}
				if(collider6 != null){
					collider6.cleanup();
					collider6 = null;
				}
				thread0 = null;
				thread1 = null;
				thread2 = null;
				thread3 = null;
				thread4 = null;
				thread5 = null;
				thread6 = null;
				iv_advance_multiplier++;
				System.gc();
			}
		}
	}//end of start method
	
	/**
	 * Advances all 16-Byte initialization vectors to new values.
	 */
	public void advanceIV16(){
		int rounds = iv_advance_multiplier * 6;
		for(int j=0; j<rounds; j++){
			for(int i=12; i>=0; i--){
				Y1_START_16[i]++;
				if(Y1_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y2_START_16[i]++;
				if(Y2_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y3_START_16[i]++;
				if(Y3_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y4_START_16[i]++;
				if(Y4_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y5_START_16[i]++;
				if(Y5_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y6_START_16[i]++;
				if(Y6_START_16[i] != 0){
					break;
				}
			}
			for(int i=12; i>=0; i--){
				Y7_START_16[i]++;
				if(Y7_START_16[i] != 0){
					break;
				}
			}
		}
		System.out.println("Y1_START_16 advanced to: "+new DataWrapper(Y1_START_16).toString());
		System.out.println("Y2_START_16 advanced to: "+new DataWrapper(Y2_START_16).toString());
		System.out.println("Y3_START_16 advanced to: "+new DataWrapper(Y3_START_16).toString());
		System.out.println("Y4_START_16 advanced to: "+new DataWrapper(Y4_START_16).toString());
		System.out.println("Y5_START_16 advanced to: "+new DataWrapper(Y5_START_16).toString());
		System.out.println("Y6_START_16 advanced to: "+new DataWrapper(Y6_START_16).toString());
	}//end of advanceIV16 method

	/**
	 * Advances all 6-Byte initialization vectors to new values.
	 */
	public void advanceIV6(){
		int rounds = iv_advance_multiplier * 6;
		for(int j=0; j<rounds; j++){
			for(int i=2; i>=0; i--){
				Y1_START_6[i]++;
				if(Y1_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y2_START_6[i]++;
				if(Y2_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y3_START_6[i]++;
				if(Y3_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y4_START_6[i]++;
				if(Y4_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y5_START_6[i]++;
				if(Y5_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y6_START_6[i]++;
				if(Y6_START_6[i] != 0){
					break;
				}
			}
			for(int i=2; i>=0; i--){
				Y7_START_6[i]++;
				if(Y7_START_6[i] != 0){
					break;
				}
			}
		}
		System.out.println("Y1_START_6 advanced to: "+new DataWrapper(Y1_START_6).toString());
		System.out.println("Y2_START_6 advanced to: "+new DataWrapper(Y2_START_6).toString());
		System.out.println("Y3_START_6 advanced to: "+new DataWrapper(Y3_START_6).toString());
		System.out.println("Y4_START_6 advanced to: "+new DataWrapper(Y4_START_6).toString());
		System.out.println("Y5_START_6 advanced to: "+new DataWrapper(Y5_START_6).toString());
		System.out.println("Y6_START_6 advanced to: "+new DataWrapper(Y6_START_6).toString());
	}//end of advanceIV6 method
	
	//---------------------static main---------------------------------
	public static void main(String[] args){
		//check args for mode ====================
		if(args.length > 0){
			if(args[0].equals("-6")){
				threads = 6;
			}
			else if(args[0].equals("-8")){
				threads = 8;
			}
		}
		if(args.length > 1){
			try{
				int k = Integer.parseInt(args[1]);
				if(k > 0 && k <= 32){
					current_k = k;
				}
				else{
					System.err.print("Second arg for starting k. Must be an integer > 0 and <= 32");
					System.exit(1);
				}
			}
			catch(NumberFormatException ex){
				System.err.print("Second arg for starting k. Must be > 0 and <= 32");
				System.exit(1);
			}
		}
		if(args.length > 2){
			try{
				int n = Integer.parseInt(args[2]);
				if(n > 0){
					iv_advance_multiplier = n;
				}
				else{
					System.err.print("Third arg for IV advance multiplier. Must be an integer > 0.");
					System.exit(1);
				}
			}
			catch(NumberFormatException ex){
				System.err.print("Third arg for IV advance multiplier. Must be an integer > 0.");
				System.exit(1);
			}
		}
		if(args.length > 3){
			try{
				int m = Integer.parseInt(args[3]);
				if(m > 0){
					max_tree_size = m;
				}
				else{
					System.err.print("Fourth arg for Max Tree Size. Must be an integer > 0.");
					System.exit(1);
				}
			}
			catch(NumberFormatException ex){
				System.err.print("Fourth arg for Max Tree Size. Must be an integer > 0.");
				System.exit(1);
			}
		}
		//arg check done ========================
		
		while(true){
			Collide collide = new Collide();
			collide.advanceIV6();
			System.out.println("$$$$$$$$$$$$$$ -- Starting k="+current_k+" -- $$$$$$$$$$$$$$");
			collide.start();
			System.out.println("$$$$$$$$$$$$$$ -- Finished k="+current_k+" -- $$$$$$$$$$$$$$");
			
			Path file = Paths.get(FILE_NAME+current_k+".txt");
			List<String> lines = null;
			if(collider0_X_result != null && collider0_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider0_X_result.toString());
				System.out.println(collider0_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider0_X_result.toString(),collider0_Y_result.toString());
			}
			else if(collider1_X_result != null && collider1_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider1_X_result.toString());
				System.out.println(collider1_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider1_X_result.toString(),collider1_Y_result.toString());
			}
			else if(collider2_X_result != null && collider2_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider2_X_result.toString());
				System.out.println(collider2_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider2_X_result.toString(),collider2_Y_result.toString());
			}
			else if(collider3_X_result != null && collider3_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider3_X_result.toString());
				System.out.println(collider3_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider3_X_result.toString(),collider3_Y_result.toString());
			}
			else if(collider4_X_result != null && collider4_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider4_X_result.toString());
				System.out.println(collider4_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider4_X_result.toString(),collider4_Y_result.toString());
			}
			else if(collider5_X_result != null && collider5_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider5_X_result.toString());
				System.out.println(collider5_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider5_X_result.toString(),collider5_Y_result.toString());
			}
			else if(collider6_X_result != null && collider6_Y_result != null){
				System.out.println("Results: ");
				System.out.println(collider6_X_result.toString());
				System.out.println(collider6_Y_result.toString());
				System.out.println();
				lines = Arrays.asList(collider6_X_result.toString(),collider6_Y_result.toString());
			}
			try{
				Files.write(file, lines, Charset.forName("UTF-8"));
			}
			catch(IOException ex){
				ex.printStackTrace();
			}
			collider0_X_result = null;
			collider0_Y_result = null;
			collider1_X_result = null;
			collider1_Y_result = null;
			collider2_X_result = null;
			collider2_Y_result = null;
			collider3_X_result = null;
			collider3_Y_result = null;
			collider4_X_result = null;
			collider4_Y_result = null;
			collider5_X_result = null;
			collider5_Y_result = null;
			collider6_X_result = null;
			collider6_Y_result = null;
			if(current_k < 32){
				current_k++;
			}
			else{
				break;
			}
		}
	}//end of main method
	
	//---------------------static methods------------------------------
	/**
	 * Provides functionality for a self-contained process of finding partial 
	 * hash collisions under the current parameters. Each <code>RunnableCollider</code> object 
	 * is meant to operate independently, as a closed system, in its own thread. 
	 * 
	 * <p>Operation will continue until an appropriate collision is found or the thread is 
	 * stopped externally.
	 * 
	 * @author Robert Thompson
	 * @since 11-07-2016
	 */
	private class RunnableCollider implements Runnable{
		
		/**
		 * The ID number for the thread running this object.
		 */
		private int threadNumber;
		/**
		 * Whether or not this object is currently performing its hash-comparison operations.
		 */
		private boolean running;
		/**
		 * The Y (pre-hash) value currently being processed.
		 */
		private DataWrapper currentY;
		/**
		 * Stores each previously generated hash value (as a keys) paired with the 
		 * value that was used to generate it for efficient comparison with subsequently 
		 * generated hash values. 
		 */
		private TreeMap<DataWrapper,DataWrapper> hashValues;
		/**
		 * <code>MessageDigest</code> object used to access the SHA-256 hash function.
		 */
		private MessageDigest digest;
		
		/**
		 * Creates a runnable collision-finder with the specified thread number.
		 * 
		 * <p>Note that the current configuration uses the 6-Byte IV values.
		 * 
		 * @param threadNumber the identification number for the thread this 
		 * object will be assigned to. (only accepts values 0-6)
		 */
		public RunnableCollider(int threadNumber){
			this.threadNumber = threadNumber;
			hashValues = new TreeMap<DataWrapper,DataWrapper>();
			try{
				digest = MessageDigest.getInstance("SHA-256");
			}
			catch(NoSuchAlgorithmException ex){
				System.err.print("Unable to load SHA-256.");
				System.exit(1);
			}
			switch(threadNumber){
			case 0:
				currentY = new DataWrapper(Y1_START_6);
				break;
			case 1:
				currentY = new DataWrapper(Y2_START_6);
				break;
			case 2:
				currentY = new DataWrapper(Y3_START_6);
				break;
			case 3:
				currentY = new DataWrapper(Y4_START_6);
				break;
			case 4:
				currentY = new DataWrapper(Y5_START_6);
				break;
			case 5:
				currentY = new DataWrapper(Y6_START_6);
				break;
			case 6:
				currentY = new DataWrapper(Y7_START_6);
				break;
			default:
				System.err.print("Invalid thread number.");
				System.exit(1);
			}
		}//end of constructor

		/**
		 * Performs the core collision-finding operations until a collision is 
		 * successfully found, or the thread is stopped by the controller.
		 * 
		 * <p>The search is performed by checking the hash of each new value 
		 * against the hashes already generated (and thus stored in the tree). 
		 * If the tree already contains the hash-value, a collision has been 
		 * found. If it does not contain the value, the value is added to the 
		 * tree for later use (unless the tree has reached its maximum size, 
		 * in which case the value is discarded).
		 */
		@Override
		public void run(){
			running = true;
			while(running){
				DataWrapper currentYHash = hash(currentY);//hash current y
				if(hashValues.containsKey(currentYHash)){
					DataWrapper x = hashValues.get(currentYHash);
					if(!currentY.equals(x)){
						setResults(x,currentY);
						running = false;
					}
					else{
						if(threads != 2){
							currentY = incrementData(currentY);
						}
						else{
							currentY = decrementData(currentY);
						}
					}
				}
				else{ 
					if(hashValues.size() < max_tree_size){
						hashValues.put(currentYHash, currentY);
					}
					if(threads != 2){
						currentY = incrementData(currentY);
					}
					else{
						currentY = decrementData(currentY);
					}
				}
				if(running == true && Thread.interrupted()){
					running = false;
				}
			}
		}//end of run method

		/**
		 * Increases the numerical value of the data in the specified 
		 * <code>DataWrapper</code> by one.
		 * 
		 * @param dataWrapper the value to increment.
		 * @return a new DataWrapper object with the altered value.
		 */
		private DataWrapper incrementData(DataWrapper dataWrapper){
			DataWrapper returnValue = new DataWrapper(dataWrapper);
			for(int i=returnValue.data.length-1; i>=0; i--){
				returnValue.data[i]++;
				if(returnValue.data[i] != 0){
					break;
				}
			}
			return returnValue;
		}//end of incrementData method

		/**
		 * Decreases the numerical value of the data in the specified 
		 * <code>DataWrapper</code> by one.
		 * 
		 * @param dataWrapper the value to decrement.
		 * @return a new DataWrapper object with the altered value.
		 */
		private DataWrapper decrementData(DataWrapper dataWrapper){
			DataWrapper returnValue = new DataWrapper(dataWrapper);
			for(int i=returnValue.data.length-1; i>=0; i--){
				returnValue.data[i]--;
				if(returnValue.data[i] != -1){
					break;
				}
			}
			return returnValue;
		}//end of decrementData method
		
		/**
		 * Runs the hash function on the specified data, returning a new 
		 * <code>DataWrapper</code> object containing the resulting value.
		 * The returned value is cropped to the current K-Byte length that 
		 * is being searched for.
		 * 
		 * @param dataWrapper the value to be hashed.
		 * @return the DataWrapper object containing the resulting hash value.
		 */
		private DataWrapper hash(DataWrapper dataWrapper){
			byte[] hashResult = digest.digest(dataWrapper.data);
			byte[] kResult = new byte[current_k];
			int offset = 32-current_k;
			for(int i=0; i<current_k; i++){
				kResult[i] = hashResult[i+offset];
			}
			return new DataWrapper(kResult);
		}//end of hash method

		/**
		 * Sets the values of the result variables corresponding to the 
		 * object's thread.
		 * 
		 * @param x the first value.
		 * @param y the second value.
		 */
		private void setResults(DataWrapper x, DataWrapper y){
			switch(threadNumber){
			case 0:
				collider0_X_result = x;
				collider0_Y_result = y;
				break;
			case 1:
				collider1_X_result = x;
				collider1_Y_result = y;
				break;
			case 2:
				collider2_X_result = x;
				collider2_Y_result = y;
				break;
			case 3:
				collider3_X_result = x;
				collider3_Y_result = y;
				break;
			case 4:
				collider4_X_result = x;
				collider4_Y_result = y;
				break;
			case 5:
				collider5_X_result = x;
				collider5_Y_result = y;
				break;
			case 6:
				collider6_X_result = x;
				collider6_Y_result = y;
			}
		}//end of setResults method
		
		/**
		 * Clears all data and object references, allowing garbage collection 
		 * to make memory available for the next run.
		 */
		public void cleanup(){
			currentY = null;
			digest = null;
			hashValues.clear();
			hashValues = null;
		}//end of cleanup method
		
	}//end of RunnableCollider class
	
	/**
	 * Serves as a <code>Compareable</code> wrapper for the binary values that 
	 * are to be used for finding partial hash collisions.
	 * 
	 * @author Robert Thompson
	 * @since 11-07-2016
	 */
	public class DataWrapper implements Comparable<DataWrapper>{
		
		/**
		 * The binary value held by this <code>DataWrapper</code> object.
		 */
		public byte[] data;

		/**
		 * Creates a wrapper object holding the binary value represented by 
		 * the specified byte array.
		 * 
		 * @param data the binary value to be placed in the wrapper.
		 */
		public DataWrapper(byte[] data){
			if(data != null){
				this.data = data;
			}
			else{
				data = new byte[0];
			}
		}//end of constructor

		/**
		 * Creates a wrapper object holding the same binary value held by 
		 * the specified <code>DataWrapper</code> object.
		 * 
		 * @param copy the <code>DataWrapper</code> object whose binary 
		 * value is to be copied.
		 */
		public DataWrapper(DataWrapper copy){
			data = new byte[copy.data.length];
			for(int i=0; i<data.length; i++){
				data[i] = copy.data[i];
			}
		}//end of copy constructor

		/**
		 * Compares this object with the specified object.
		 * 
		 * @return true if the specified object is a <code>DataWrapper</code> object 
		 * containing a binary value that is identical to the one contained by 
		 * this object. Otherwise, returns false.
		 */
		@Override
		public boolean equals(Object other){
			if(other instanceof DataWrapper){
				return Arrays.equals(data, ((DataWrapper)other).data);
			}
			else{
				return false;
			}
		}//end of equals method

		/**
		 * 
		 */
		@Override
		public int hashCode(){
			return Arrays.hashCode(data);
		}//end of hashCode method

		/**
		 * Natural comparison method allowing <code>DataWrapper</code> objects 
		 * to be used as keys in a map.
		 * 
		 * <p>Note that the resulting comparison of this method does not (necessarily) 
		 * conform to a numerical ordering of the binary values contained in this object 
		 * and the specified <code>DataWrapper</code> object.
		 */
		@Override
		public int compareTo(DataWrapper other){
			if(data.length < other.data.length){
				return -1;
			}
			else if(data.length > other.data.length){
				return 1;
			}
			else{
				int returnValue = 0;
				for(int i=0; i<data.length; i++){
					if(data[i] < other.data[i]){
						returnValue = -1;
						break;
					}
					else if(data[i] > other.data[i]){
						returnValue = 1;
						break;
					}
				}
				return returnValue;
			}
		}//end of compareTo method
		
		/**
		 * Returns a readable string of the binary value contained in this object.
		 */
		@Override
		public String toString(){
			String returnValue = "";
			int[] printable = new int[data.length];
			for(int i=0; i<data.length; i++){
				printable[i] = data[i] & 0xFF;
				returnValue = returnValue + String.format("%8s", Integer.toBinaryString(printable[i])).replace(" ", "0");
			}
			return returnValue;
		}//end of toString method
		
	}//end of DataWrapper class
	
}//end of Collide class