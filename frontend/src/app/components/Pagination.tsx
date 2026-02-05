import React from 'react';
import { FaChevronLeft, FaChevronRight } from 'react-icons/fa';

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  totalCount: number;
  itemsPerPage: number;
}

const Pagination: React.FC<PaginationProps> = ({ currentPage, totalPages, onPageChange, totalCount, itemsPerPage }) => {
  const getPageNumbers = () => {
    const pages: (string | number)[] = [];
    const maxPagesToShow = 3;
    const endPage = totalPages;

    if (currentPage <= 2) {
      for (let i = 1; i <= Math.min(maxPagesToShow, endPage); i++) {
        pages.push(i);
      }
      if (endPage > maxPagesToShow + 1) {
        pages.push('...');
      }
      if (endPage > maxPagesToShow) {
        pages.push(endPage);
      }
    } else if (currentPage >= endPage - 1) {
      pages.push(1);
      pages.push('...');
      for (let i = endPage - (maxPagesToShow - 1); i <= endPage; i++) {
        pages.push(i);
      }
    } else {
      pages.push(1);
      pages.push('...');
      pages.push(currentPage - 1);
      pages.push(currentPage);
      pages.push(currentPage + 1);
      if (currentPage + 2 < endPage) {
        pages.push('...');
      }
      if (currentPage + 1 < endPage) {
        pages.push(endPage);
      }
    }
    return pages;
  };

  const pageNumbers = getPageNumbers();

  if (totalPages <= 1) return null;

  return (
    <div className="flex flex-col sm:flex-row justify-between items-center mt-6 gap-4">
      <p className="text-sm text-gray-600">
        Menampilkan <span className="font-semibold">{itemsPerPage}</span> dari <span className="font-semibold">{totalCount}</span> hasil
      </p>

      <nav aria-label="Pagination">
        <ul className="flex items-center -space-x-px h-10 text-base">
          <li>
            <button
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="flex items-center justify-center px-2 h-10 ms-0 leading-tight text-gray-500 bg-gray-7/30  rounded-s-lg hover:bg-gray-7/50 hover:text-gray-200 disabled:hover:text-gray-500 disabled:opacity-40 disabled:hover:bg-gray-7/30"
            >
              <FaChevronLeft />
            </button>
          </li>

          {pageNumbers.map((page, index) => (
            <li key={`page-${page}-${index}`}>
              {typeof page === 'number' ? (
                <button
                  onClick={() => onPageChange(page)}
                  aria-current={currentPage === page ? 'page' : undefined}
                  className={`flex items-center justify-center px-4 h-10 leading-tight ${currentPage === page ? 'z-10 text-gray-200  bg-gray-7/40' : 'text-gray-200 bg-gray-7/20 hover:bg-gray-7/30 hover:text-gray-200'}`}
                >
                  {page}
                </button>
              ) : (
                <span className="flex items-center justify-center px-4 h-10 leading-tight text-gray-500 bg-gray-7/20 border-transparent">{page}</span>
              )}
            </li>
          ))}

          <li>
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="flex items-center justify-center px-4 h-10 leading-tight text-gray-500 bg-gray-7/20  rounded-e-lg hover:bg-gray-7/30 hover:text-gray-200 disabled:text-gray-500 disabled:opacity-50"
            >
              <FaChevronRight />
            </button>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export default Pagination;
