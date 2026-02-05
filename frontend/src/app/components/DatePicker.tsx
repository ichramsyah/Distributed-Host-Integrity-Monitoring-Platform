// app/components/DatePicker.tsx

'use client';

import React, { useState, useRef, useEffect } from 'react';
import { DayPicker } from 'react-day-picker';
import 'react-day-picker/dist/style.css';
import { format } from 'date-fns';
import { id } from 'date-fns/locale';
import { FaRegCalendarAlt } from 'react-icons/fa';

interface DatePickerProps {
  selectedDate: string;
  onDateSelect: (date: string) => void;
  resetToToday: () => void;
  availableDates: Set<number>;
}

export const DatePicker: React.FC<DatePickerProps> = ({ selectedDate, onDateSelect, resetToToday, availableDates }) => {
  const [isOpen, setIsOpen] = useState(false);
  const pickerRef = useRef<HTMLDivElement>(null);

  const handleDayClick = (date: Date | undefined) => {
    if (date) {
      onDateSelect(format(date, 'yyyy-MM-dd'));
      setIsOpen(false);
    }
  };

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [pickerRef]);

  const disabledDays = (date: Date) => {
    const normalizedDate = new Date(date).setHours(0, 0, 0, 0);
    return !availableDates.has(normalizedDate);
  };

  const lastAvailableDate = new Date(Math.max(...Array.from(availableDates)));

  return (
    <div className="relative" ref={pickerRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2 pb-3 text-sm font-medium text-gray-1 bg-gray-4/20 hover:rounded-[20px] rounded-[6px] focus:rounded-[20px] focus:outline-none transition-all cursor-pointer"
      >
        <FaRegCalendarAlt />
        <span>{selectedDate === 'Hari Ini' ? 'Hari Ini' : format(new Date(selectedDate), 'dd MMMM yyyy', { locale: id })}</span>
      </button>

      {isOpen && (
        <div className="absolute px-5 py-2 md:right-0 right-[-195px] z-10 mt-2 bg-neutral-900 rounded-xl shadow-lg text-gray-100">
          <DayPicker
            mode="single"
            selected={new Date(selectedDate)}
            onSelect={handleDayClick}
            locale={id}
            defaultMonth={lastAvailableDate}
            footer={
              <button
                onClick={() => {
                  resetToToday();
                  setIsOpen(false);
                }}
                className="w-full text-center py-2 text-sm cursor-pointer text-gray-100 hover:underline"
              >
                Kembali ke Hari Ini
              </button>
            }
            classNames={{
              months: 'relative',
              month: 'space-y-2',
              caption_label: 'text-base font-medium mt-2',
              nav: 'absolute right-0 top-0 flex items-center gap-2 ',
              nav_button: 'text-gray-100 hover:text-gray-800 transition p-1 rounded-full hover:bg-gray-200',
              table: 'w-full border-collapse',
              head_row: 'flex justify-between text-gray-500 font-medium mb-2',
              head_cell: 'w-9 text-center text-xs',
              row: 'flex justify-between',
              cell: 'w-9 h-9 flex items-center justify-center rounded-md text-sm cursor-pointer transition-all hover:bg-gray-200',
              day_selected: 'bg-blue-200 text-white hover:bg-blue-300',
            }}
          />
        </div>
      )}
    </div>
  );
};
