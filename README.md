SDN Load Balancing using Mininet and POX
Introduction:

With the growing complexity of modern networks, efficient traffic management has become a critical challenge. Traditional architectures couple the control and data planes, limiting flexibility. Software-Defined Networking (SDN) addresses this by separating the two, enabling centralized control and programmability.

This project leverages Mininet and the POX controller to implement dynamic load balancing. Two algorithms are integrated: Round Robin and Least Connection, showcasing how SDN can optimize traffic routing and improve overall performance.

⚙️ Features

Dynamic load balancing using:

Round Robin (RR)

Least Connection (LC)

Centralized control with POX controller

MAC-to-port mapping for efficient communication

Support for multiple clients and servers in a virtual topology

Real-time adaptability to traffic conditions

Tools & Technologies

Mininet – Network emulation

POX Controller – Python-based SDN controller

Python – Custom scripts for load balancing & communication

🌐 Network Topology

8–10 Clients → Generate traffic

1 Switch → Connects clients & servers

4 Servers → Python-based web servers with identical content

Virtual IP (VIP) → Acts as the load balancer for routing requests

 Clients ----> Switch ----> Servers
          \          |
           \---- POX Controller

Implementation

Setup Mininet to create clients, servers, and a switch.

Run Python web servers on backend servers.

Start POX controller with custom script:

./pox.py forwarding.l2_learning load_balancer --algorithm=rr
./pox.py forwarding.l2_learning load_balancer --algorithm=lc


Clients send requests to the VIP (10.0.0.34), which forwards traffic using the selected algorithm.

Load Balancing Algorithms

Round Robin (RR): Distributes traffic equally among servers.

Least Connection (LC): Routes traffic to the server with the fewest active connections.

References

S. Kaur, N. Kumar, and J. Singh, "Load Balancing in Software Defined Network using Mininet and POX," International Journal of Computer Applications, vol. 122, no. 2, pp. 12–16, 2015.
