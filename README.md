# Juniper SDN Throwdown 2019

SDN Throwdown overview: http://www.sdnthrowdown.com/

| name | linkedin profile |
| ------ | ------ |
| Jialu Sun | [https://www.linkedin.com/in/jialu-sun-cse/]|
| Bo Cheng | [https://www.linkedin.com/in/bo-cheng/]|
| Litong Shen | [https://www.linkedin.com/in/litong-amanda-shen-b378727a/]|

Presentation ppt is located in docs folder.

## Problem Statement

Problem Statement
1. You are given access to a shared volatile network where
conditions change without warning
2.  You are given management tool to interact with the network
3.  Your mission is to generate traffic, transport it across this network and receive it at the other side

Problem Statement: Step 1

1.  Visualize the network
2.  Use the tools to describe what is going on and describe it
 Topology, health, utilization, etc.
 
Problem Statement: Step 2

3. Get some traffic across the network
4. Demonstrate that your traffic is crossing the network
5. This traffic can be anything: be creative

Problem Statement: Step 3

6. Manage the network
7. Use the tools to alter the network in near-real-time to optimize
your path
8. React to changes and utilization
9. You must identify the characteristics that you are optimizing
for

## Background For the Environment

- A network managed by NorthStar. 
- Shared core network of 8 P routers
- Each group has its own PE routers and NorthStar Controller. 
- LSPs use Segment Routing.
- Network telemetry collected by the NorthStar Controller.
- NorthStar notifies failures in the network.
- A pair of VM's dedicated to each team; on the east and west sides of the network.
- Traffic generators that vary in order to cause background north-south interference.
- Links in the network will occasionally fail.

![设计图](/image/design.png)
