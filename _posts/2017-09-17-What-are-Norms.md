---
layout: post
title:  "What are Norms? l1, l2...lp Normalization"
date:   2017-09-17 12:06:54 -0700
categories: [MathScience]
use_math: true
---
What is a norm?

Mathematically a norm is a total size or length of all vectors in a vector space or matrices. For simplicity, we can say that the higher the norm is, the bigger the (value in) matrix or vector is. Norm may come in many forms and many names, including these popular name: Euclidean distance, Mean-squared Error, etc.

Most of the time you will see the norm appears in an equation like this:
$$
\left \| x \right \| $$ where x  can be a vector or a matrix.


For example, a Euclidean norm of a vector
$$ a = \begin{bmatrix}  3  \\  -2  \\  1  \end{bmatrix} $$ is
$\left \| a \right \|l_2=\sqrt{3^2+(-2)^2+1^2}=3.742 $
which is the size of vector a

The above example shows how to compute a Euclidean norm, or formally called an $$l_2$$-norm. There are many other types of norms that beyond our explanation here, actually for every single <bold>real number<bold>, there is a norm correspond to it  > Notice the emphasized word real number, that means it not limited to the only integer.

Formally the $$l_p$$-norm of x is defined as:
$$
\left \| x \right \|l_p = \sqrt[p]{\sum_{i}\left | x_i \right |^p}$$  where
$$p \epsilon \mathbb{R}$$
That’s it! A p-th-root of a summation of all elements to the p-th power is what we call a norm.

The interesting point is even though every $$l_p$$-norm look similar to each other, their mathematical properties are very different and thus their applications are dramatically different too. Hereby we are going to look into some of these norms in details.

#### $$l_0$$-norm

The first norm we are going to discuss is a $$l_0$$-norm. By definition, $$l_0$$-norm of $$x$$ is

$$\left \| x \right \|l_0 = \sqrt[0]{\sum_{i}x_i^0}$$

Strictly speaking, $$l_0$$-norm is not actually a norm. It is a cardinality function which has its definition in the form of $$l_p$$-norm, though many people call it a norm. It is a bit tricky to work with because there is a presence of zeroth-power and zeroth-root in it. Obviously, any $$x>0$$ will become one, but the problems of the definition of zeroth-power and especially zeroth-root is messing things around here. So in reality, most mathematicians and engineers use this definition of $$l_0$$-norm instead:

$$\left \| x \right \|l_0 = \#(i | x_i \neq 0)$$

that is a total number of non-zero elements in a vector.

Because it determines the number of non-zero elements, there are so many applications that use $$l_0$$-norm. Recently, it gained more focus because of the rise of the Compressive Sensing scheme, which calculates the sparsest solution of the under-determined linear system. The sparsest solution means the solution which has fewest non-zero entries, i.e. the lowest $$l_0$$-norm. This is usually regarded as an optimization problem of $$l_0$$-norm or $$l_0$$-optimization.

To be clear l0 norm is not a norm. It satisfies only two of the three necessary properties of a norm:
that it is zero only for the all-zero vector, and the triangle inequality. It is not, however, positively homogeneous. And unlike all true norms, it is not convex.It is the cardinality function.


#### $$l_0$$-optimization

Many applications, including Compressive Sensing, try to minimize the $$l_0$$-norm of a vector corresponding to some constraints, hence called “$$l_0$$-minimization”. A standard minimization problem is formulated as:

$$min \left \| x \right \|l_0$$ subject to $$Ax = b$$

However, doing so is not an easy task. Because the lack of $$l_0$$-norm’s mathematical representation, $$l_0$$-minimization is regarded by computer scientist as a NP-hard problem, simply says that it’s too complex and almost impossible to solve.

In many cases, $$l_0$$-minimization problem is relaxed to be higher-order norm problem such as $$l_1$$-minimization and $$l_2$$-minimization.

#### $$l_1$$-norm

Following the definition of norm, $$l_1$$-norm of x is defined as
$$
\left \| x \right \|l_1 = \sum_{i} \left | x_i \right |
$$
This norm is quite common among the norm family. It has many names and many forms of various fields, namely Manhattan norm is its nickname. If the l_1-norm is computed for a difference between two vectors or matrices, that is
$
SAD(x_1,x_2) = \left \| x_1-x_2 \right \|l_1 = \sum \left | x_{1_i}-x_{2_i} \right |
$

it is called Sum of Absolute Difference (SAD) among computer vision scientists.

In more general case of signal difference measurement, it may be scaled to a unit vector by:

$
MAE(x_1,x_2) = \frac{1}{n} \left \| x_1-x_2 \right \|l_1 = \frac {1} {n} \sum \left | x_{1_i} - x_{2_i} \right |
$
where $$n$$ is a size of $$x$$.

which is known as Mean-Absolute Error (MAE).

#### $$l_2$$-norm

The most popular of all norm is the $$l_2$$-norm. It is used in almost every field of engineering and science as a whole. Following the basic definition, l_2-norm is defined as
$
\left \| x \right \|l_2 = \sqrt{\sum_{i}x_i^2}
$
$$l_2$$-norm is well known as a Euclidean norm, which is used as a standard quantity for measuring a vector difference. As in $$l_1$$-norm, if the Euclidean norm is computed for a vector difference, it is known as a Euclidean distance:
$\left \| x_1-x_2 \right \|l_2 = \sqrt{\sum_i (x_{1_i}-x_{2_i})^2}$
or in its squared form, known as a Sum of Squared Difference among Computer Vision scientists:
$
SSD(x_1,x_2) = \left \| x_1-x_2 \right \|l_2^2 = \sum_i (x_{1_i}-x_{2_i})^2
$
It’s most well-known application in the signal processing field is the Mean-Squared Error (MSE) measurement, which is used to compute a similarity, a quality, or a  correlation between two signals. MSE is
$
MSE(x_1,x_2) = \frac{1}{n} \left \| x_1-x_2 \right \|l_2^2 = \frac{1}{n} \sum_i (x_{1_i}-x_{2_i})^2
$
As previously discussed in $$l_0$$-optimization section, because of many issues from both a computational view and a mathematical view, many $$l_0$$-optimization problems relax themselves to become $$l_1$$– and $$l_2$$-optimization instead. Because of this, we will now discuss the optimization of $$l_2$$.

#### $$l_2$$-optimization

As in $$l_0$$-optimization case, the problem of minimizing $$l_2$$-norm is formulated by
$min \left \| x \right \|l_2$ subject to $$Ax = b$$

Assume that the constraint matrix A has [full-rank](http://stattrek.com/matrix-algebra/matrix-rank.aspx), this problem is now a underdetermined system which has infinite solutions. The goal, in this case, is to draw out the best solution, i.e. has lowest $$l_2$$-norm, from these infinitely many solutions. This could be a very tedious work if it was to be computed directly. Luckily it is a mathematical trick that can help us a lot in this work.

By using a trick of Lagrange multipliers, we can then define a Lagrangian
$\mathfrak{L}(\boldsymbol{x}) = \left \| \boldsymbol{x} \right \|l_2^2+\lambda^{T}(\boldsymbol{Ax}-\boldsymbol{b})$
where $$\lambda$$ is the introduced Lagrange multipliers. Take derivative of this equation equal to zero to find an optimal solution and get
$ \hat{\boldsymbol{x}}_{opt} = -\frac{1}{2} \boldsymbol{A}^{T} \lambda $
plug this solution into the constraint to get
$ \boldsymbol{A}\hat{\boldsymbol{x}}_{opt} = -\frac{1}{2}\boldsymbol{AA}^{T}\lambda=\boldsymbol{b} $
$ \lambda=-2(\boldsymbol{AA}^{T})^{-1}\boldsymbol{b} $
and finally
$ \hat{\boldsymbol{x}}_{opt}=\boldsymbol{A}^{T} (\boldsymbol{AA}^{T})^{-1} \boldsymbol{b}=\boldsymbol{A}^{+} \boldsymbol{b} $
By using this equation, we can now instantly compute an optimal solution of the $$l_2$$-optimization problem. This equation is well known as the Moore-Penrose Pseudoinverse and the problem itself is usually known as Least Square problem, Least Square regression, or Least Square optimization.
However, even though the solution of Least Square method is easy to compute, it’s not necessary to be the best solution. Because of the smooth nature of $$l_2$$-norm itself,  it is hard to find a single, best solution for the problem.
In contrary, the $$l_1$$-optimization can provide much better result than this solution.

#### $$l_1$$-optimization

As usual, the $$l_1$$-minimization problem is formulated as

$min \left \| x \right \|l_1$ subject to $$Ax = b$$

Because the nature of $$l_1$$-norm is not smooth as in the $$l_2$$-norm case, the solution of this problem is much better and more unique than the $$l_2$$-optimization.

However, even though the problem of $$l_1$$-minimization has almost the same form as the $$l_2$$-minimization, it’s much harder to solve. Because this problem doesn’t have a smooth function, the trick we used to solve $$l_2$$-problem is no longer valid.  The only way left to find its solution is to search for it directly. Searching for the solution means that we have to compute every single possible solution to find the best one from the pool of "infinitely many" possible solutions.

Since there is no easy way to find the solution for this problem mathematically, the usefulness of $$l_1$$-optimization is very limited for decades. Until recently, the advancement of the computer with high computational power allows us to "sweep" through all the solutions. By using many helpful algorithms, namely the Convex Optimization algorithm such as linear programming, or non-linear programming, etc. it’s now possible to find the best solution to this question. Many applications that rely on $$l_1$$-optimization, including the Compressive Sensing, are now possible.

There are many toolboxes for $$l_1$$-optimization available nowadays.  These toolboxes usually use different approaches and/or algorithms to solve the same question. The example of these toolboxes are [l1-magic](http://jrom.ece.gatech.edu/index-8/), [SparseLab](http://sparselab.stanford.edu/), ISAL1,

Now that we have discussed many members of norm family, starting from $$l_0$$-norm, $$l_1$$-norm, and $$l_2$$-norm. Let's move on to the next one. As we discussed in the very beginning that there can be any $$l-whatever$$ norm following the same basic definition of the norm, it’s going to take a lot of time to talk about all of them. Fortunately, apart from $$l_0$$-, $$l_1$$– , and $$l_2$$-norm, the rest of them usually uncommon and therefore don’t have so many interesting things to look at. So we’re going to look at the extreme case of the norm which is a  $l_{\infty}$-norm l-infinity norm.

#### $$l_{\infty}$$norm

As always, the definition for $$l_{\infty}$$-norm is
$
\left \| x \right \|l_{\infty} = \sqrt[\infty]{\sum_i x_i^{\infty}}
$
Now, this definition looks tricky again, but actually, it is quite straight forward. Consider the vector $\boldsymbol{x}$, let’s say if $x_j$ is the highest entry in the vector  $$\boldsymbol{x}$$, by the property of the infinity itself, we can say that
$
x_j^{\infty}\gg x_i^{\infty} \forall i \neq j
$
 then
$
\sum_i x_i^{\infty} = x_j^{\infty}
$
then
$
\left \| x \right \|l_{\infty} = \sqrt[\infty]{\sum_i x_i^{\infty}} = \sqrt[\infty]{x_j^{\infty}} = \left | x_j \right |
$
Now we can simply say that the $$l_{\infty}$$-norm is
$
\left \| x \right \|l_{\infty} = max(\left | x_i \right |)
$
that is the maximum entries’ magnitude of that vector. That surely demystified the meaning of $$l_{\infty}$$-norm

Now we have discussed the whole family of the norm from $$l_0$$ to $$l_{\infty}$$, I hope that this discussion would help to understand the meaning of norm, its mathematical properties, and its real-world implication.

Reference and further reading:

[Mathematical Norm] – (Wikipedia)

[Mathematical Norm](https://rorasa.wordpress.com/2012/05/13/l0-norm-l1-norm-l2-norm-l-infinity-norm/)

Michael Elad – “Sparse and Redundant Representations: From Theory to Applications in Signal and Image Processing”, Springer, 2010.

 Linear Programming – MathWorld

Compressive Sensing – Rice University
