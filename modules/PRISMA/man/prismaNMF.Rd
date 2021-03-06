\name{prismaNMF}
\alias{prismaNMF}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
  Matrix Factorization Based on Replicate-Aware NMF
}
\description{
  Matrix factorization \eqn{A = B C} with strictly positiv matrices \eqn{B, C}
  which minimize the reconstruction error \eqn{\|A - B C\|}. This
  replicate-aware version of the non-negtive matrix factorization (NMF)
  is based on the alternating least squares
  approach and exploits the replicate information to speed up the calculation.
}
\usage{
prismaNMF(prismaData, ncomp, time = 60, pca.init = TRUE, doNorm = TRUE, oldResult = NULL)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{prismaData}{
    PRISMA data for which a NMF should be calculated.
}
  \item{ncomp}{
    either an \code{integer} or \code{prismaDimension} object specifying
    the inner dimension of the matrix factorization.
}
  \item{time}{
    seconds after which the calculation should end.
}
  \item{pca.init}{
    should the \eqn{B} matrix be initialized by a PCA.
}
  \item{doNorm}{
    should the \eqn{B} matrix normalized (i.e. all columns have the
    Euclidean length of 1).
}
  \item{oldResult}{
    re-use results of a previous run, i.e. \eqn{B} and \eqn{C} are
    pre-initialized with the values of this previous matrix
    factorization object.
}
}
\value{
  \item{prismaNMF}{Matrix factorization object containing the \eqn{B} and
    \eqn{C} matrix.}
}
\references{
Krueger, T., Gascon, H., Kraemer, N., Rieck, K. (2012)
Learning Stateful Models for Network Honeypots
\emph{5th ACM Workshop on Artificial Intelligence and Security (AISEC 2012)}, accepted

R. Albright, J. Cox, D. Duling, A. Langville, and C. Meyer. (2006)
Algorithms, initializations, and convergence for the nonnegative
matrix factorization. \emph{Technical Report 81706, North Carolina State University}
}
\author{
Tammo Krueger <tammokrueger@googlemail.com>
}
\examples{
# please see the vingette for examles
}
