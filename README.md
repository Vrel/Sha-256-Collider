# Sha-256-Collider

by Robert Thompson - Nov 7, 2016

Originally written for an assignment in a Cryptography class at Sacramento State University.

Attempts to find partial hash collisions using SHA2-256. 

## Function

As described in by the original assignment: 
> "Let’s say that X and Y are k-colliding if the last k bytes of 
> SHA2-256(X) and SHA2-256(Y) are the same. Find a k-collision for 
> the largest k you can."

Any such collisions that are discovered are automatically written to a file. For example "Collision_Output_1.txt" would contain the first 
occurrence of a k=1 collision. After finding a collision, the search begins again, looking for a collision that is one higher than the previously discovered k.

## Configuration

Command-line arguments can be used at startup to configure some options for the search. The search can be configured to run on 2, 6, or 8-core processors by passing "-2" "-6" or "-8" as the first argument, respectively. Separate searches, with unique starting points, will be run independently on each core, with one reserved for monitoring for successful searches. The search can also be configured to start searching for a specific k-collision by passing the desired k (number only, 1-32) as the second argument. For example, the arguments "-6 7" would utilize 6 processor cores while beginning the search at k=7. The initial starting point of the search can be configured by passing an integer (greater than zero) as the third argument. The initial values used for the search will be shifted by this amount, allowing either searching from a specific point, or ensuring that new values are used. The maximum size of the trees (and thus the required memory) can be configured by passing an integer (greater than zero) as the fourth argument. If no value is specified, the default is 5 million.

The JVM should be configured to utilize a large amount of memory (for example: java -Xmx8196M). Any reasonably large tree size will exceed the default maximum heap size, and the tree size should be as large as the available hardware will allow.
