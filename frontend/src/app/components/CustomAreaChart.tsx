// app/components/CustomAreaChart.tsx
'use client';

import React, { useMemo } from 'react';
import { AreaClosed } from '@visx/shape';
import { line as d3Line, curveMonotoneX } from 'd3-shape';
import { scaleTime, scaleLinear } from '@visx/scale';
import { LinearGradient } from '@visx/gradient';
import { AxisBottom, AxisLeft } from '@visx/axis';
import { GridRows } from '@visx/grid';
import { localPoint } from '@visx/event';
import { motion } from 'framer-motion';

interface HistoricalData {
  tanggal: string;
  detail: { bahaya: number; mencurigakan: number; normal: number };
}
type ChartProps = {
  data: HistoricalData[];
  width: number;
  height: number;
  onDateSelect: (date: string) => void;
};
const margin = { top: 20, right: 30, bottom: 40, left: 40 };

const getDate = (d: HistoricalData) => new Date(d.tanggal);
const getBahayaValue = (d: HistoricalData) => d.detail.bahaya;
const getMencurigakanValue = (d: HistoricalData) => d.detail.mencurigakan;
const getNormalValue = (d: HistoricalData) => d.detail.normal;

export default function CustomAreaChart({ data, width, height, onDateSelect }: ChartProps) {
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;
  const { timeScale, valueScale, pathBahaya, pathMencurigakan, pathNormal } = useMemo(() => {
    const timeScale = scaleTime({
      range: [0, innerWidth],
      domain: [Math.min(...data.map((d) => getDate(d).getTime())), Math.max(...data.map((d) => getDate(d).getTime()))],
    });

    const maxValue = Math.max(...data.map((d) => Math.max(getBahayaValue(d), getMencurigakanValue(d), getNormalValue(d))));

    const valueScale = scaleLinear({
      range: [innerHeight, 0],
      domain: [0, maxValue + maxValue * 0.1],
      nice: true,
    });
    const lineGenerator = (getValue: (d: HistoricalData) => number) =>
      d3Line<HistoricalData>()
        .x((d) => timeScale(getDate(d)))
        .y((d) => valueScale(getValue(d)))
        .curve(curveMonotoneX);

    const pathBahaya = lineGenerator(getBahayaValue)(data) || '';
    const pathMencurigakan = lineGenerator(getMencurigakanValue)(data) || '';
    const pathNormal = lineGenerator(getNormalValue)(data) || '';

    return { timeScale, valueScale, pathBahaya, pathMencurigakan, pathNormal };
  }, [data, innerWidth, innerHeight]);

  const handleDateClick = (event: React.MouseEvent<SVGRectElement>) => {
    const point = localPoint(event);
    if (!point) return;
    const x = point.x - margin.left;
    const xDate = timeScale.invert(x);
    const closest = data.reduce((prev, curr) => {
      const prevDate = getDate(prev);
      const currDate = getDate(curr);
      return Math.abs(currDate.getTime() - xDate.getTime()) < Math.abs(prevDate.getTime() - xDate.getTime()) ? curr : prev;
    });
    onDateSelect(closest.tanggal);
  };

  if (width < 10) return null;

  return (
    <div style={{ position: 'relative' }}>
      <svg width={width} height={height}>
        <rect x={0} y={0} width={width} height={height} fill="#000000ff" rx={50} />
        <LinearGradient id="grad-bahaya" from="#ff3a3aff" to="#ff3a3aff" toOpacity={0} />
        <LinearGradient id="grad-mencurigakan" from="#ffb32fff" to="#ffb32fff" toOpacity={0} />
        <LinearGradient id="grad-normal" from="#3381ffff" to="#3381ffff" toOpacity={0} />

        <g transform={`translate(${margin.left}, ${margin.top})`}>
          <GridRows scale={valueScale} width={innerWidth} stroke="#ffffff28" />
          <AxisLeft
            scale={valueScale}
            stroke="#888"
            tickStroke="#888"
            tickLabelProps={() => ({
              fill: '#888',
              fontSize: 11,
              textAnchor: 'end',
              dy: '0.33em',
            })}
          />
          <AxisBottom
            top={innerHeight}
            scale={timeScale}
            stroke="#888"
            tickStroke="#888"
            tickLabelProps={() => ({
              fill: '#888',
              fontSize: 11,
              textAnchor: 'middle',
            })}
            tickFormat={(date) => {
              if (!(date instanceof Date)) return '';
              return `${date.getDate()}/${date.getMonth() + 1}`;
            }}
          />
          <motion.g initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1, delay: 0 }}>
            <AreaClosed data={data} x={(d) => timeScale(getDate(d))} y={(d) => valueScale(getBahayaValue(d))} yScale={valueScale} fill="url(#grad-bahaya)" stroke="none" curve={curveMonotoneX} />
          </motion.g>
          <motion.g initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1, delay: 0.1 }}>
            <AreaClosed data={data} x={(d) => timeScale(getDate(d))} y={(d) => valueScale(getMencurigakanValue(d))} yScale={valueScale} fill="url(#grad-mencurigakan)" stroke="none" curve={curveMonotoneX} />
          </motion.g>

          <motion.g initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1, delay: 0.2 }}>
            <AreaClosed data={data} x={(d) => timeScale(getDate(d))} y={(d) => valueScale(getNormalValue(d))} yScale={valueScale} fill="url(#grad-normal)" stroke="none" curve={curveMonotoneX} />
          </motion.g>
          <motion.path d={pathBahaya} fill="transparent" stroke="#ff3a3aff" strokeWidth={1} strokeLinejoin="round" strokeLinecap="round" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.5, delay: 0.2 }} />
          <motion.path
            d={pathMencurigakan}
            fill="transparent"
            stroke="#ffb32fff"
            strokeWidth={1}
            strokeLinejoin="round"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: 1 }}
            transition={{ duration: 1.5, delay: 0.4 }}
          />
          <motion.path d={pathNormal} fill="transparent" stroke="#3381ffff" strokeWidth={1} strokeLinejoin="round" strokeLinecap="round" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.5, delay: 0.6 }} />
          <rect x={0} y={0} width={innerWidth} height={innerHeight} fill="transparent" onClick={handleDateClick} />
        </g>
      </svg>
    </div>
  );
}
